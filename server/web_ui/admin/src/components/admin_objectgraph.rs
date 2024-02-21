use enum_iterator::{all, Sequence};
#[cfg(debug_assertions)]
use gloo::console;
use std::fmt::{Display, Formatter};
use yew::prelude::*;

use kanidmd_web_ui_shared::constants::CSS_PAGE_HEADER;
use kanidmd_web_ui_shared::{do_request, error::FetchError, RequestMethod};
use wasm_bindgen::prelude::*;
use web_sys::HtmlInputElement;
use yew_router::Routable;

use crate::router::AdminRoute;
use kanidm_proto::v1::Entry;
use kanidmd_web_ui_shared::ui::{error_page, loading_spinner};
use kanidmd_web_ui_shared::utils::{init_graphviz, open_blank};

pub enum Msg {
    NewFilters { filters: Vec<ObjectType> },
    NewObjects { entries: Vec<Entry> },

    Error { emsg: String, kopid: Option<String> },
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Sequence)]
pub enum ObjectType {
    Group,
    BuiltinGroup,
    ServiceAccount,
    Person,
}

impl Display for ObjectType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ObjectType::Group => "Group",
            ObjectType::BuiltinGroup => "Built In Group",
            ObjectType::ServiceAccount => "Service Account",
            ObjectType::Person => "Person",
        };

        write!(f, "{str}")
    }
}

impl TryFrom<String> for ObjectType {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        all::<ObjectType>()
            .find(|x| format!("{x}") == value)
            .ok_or(())
    }
}

pub enum State {
    Waiting,
    Ready { entries: Vec<Entry> },
    Error { emsg: String, kopid: Option<String> },
}

pub struct AdminObjectGraph {
    state: State,
    filters: Vec<ObjectType>,
}

impl Component for AdminObjectGraph {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("views::objectgraph::create");

        ctx.link()
            .send_future(async { Self::fetch_objects().await.unwrap_or_else(|v| v.into()) });

        let state = State::Waiting;

        AdminObjectGraph {
            state,
            filters: vec![],
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::objectgraph::update");
        match msg {
            Msg::NewObjects { entries } => {
                #[cfg(debug_assertions)]
                console::debug!("Received new objects");
                self.state = State::Ready { entries }
            }
            Msg::NewFilters { filters } => {
                #[cfg(debug_assertions)]
                console::debug!("Received new filters");
                self.filters = filters;
            }
            Msg::Error { emsg, kopid } => self.state = State::Error { emsg, kopid },
        }

        true
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::objectgraph::changed");
        false
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            State::Waiting => self.view_waiting(),
            State::Ready { entries } => self.view_ready(ctx, &self.filters, entries),
            State::Error { emsg, kopid } => self.view_error(ctx, emsg, kopid.as_deref()),
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("views::objectgraph::rendered");
    }
}

impl AdminObjectGraph {
    fn view_waiting(&self) -> Html {
        loading_spinner()
    }

    fn view_ready(
        &self,
        ctx: &Context<Self>,
        filters: &[ObjectType],
        entries: &[Entry],
    ) -> Html {
        let typed_entries = entries
            .iter()
            .filter_map(|entry| {
                let classes = entry.attrs.get("class")?;
                let uuid = entry.attrs.get("uuid")?.first()?;

                // Logic to decide the type of each entry
                let obj_type = if classes.contains(&"group".to_string()) {
                    if uuid.starts_with("00000000-0000-0000-0000-") {
                        ObjectType::BuiltinGroup
                    } else {
                        ObjectType::Group
                    }
                } else if classes.contains(&"account".to_string()) {
                    if classes.contains(&"person".to_string()) {
                        ObjectType::Person
                    } else {
                        ObjectType::ServiceAccount
                    }
                } else {
                    return None;
                };

                // Filter out the things we want to keep, if the filter is empty we assume we want all.
                if !filters.contains(&obj_type) && !filters.is_empty() {
                    return None;
                }

                let spn = entry.attrs.get("spn")?.first()?;
                Some((spn.clone(), uuid.clone(), obj_type))
            })
            .collect::<Vec<(String, String, ObjectType)>>();

        // Vec<obj, uuid, obj's members>
        let members_of = entries
            .iter()
            .filter_map(|entry| {
                let spn = entry.attrs.get("spn")?.first()?.clone();
                let uuid = entry.attrs.get("uuid")?.first()?.clone();
                let keep = typed_entries
                    .iter()
                    .any(|(_, filtered_uuid, _)| &uuid == filtered_uuid);
                if keep {
                    Some((spn, uuid, entry.attrs.get("member")?.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Constructing graph source
        let mut sb = String::new();
        sb.push_str("digraph {\n  rankdir=\"RL\"\n");
        for (spn, _, members) in members_of {
            members
                .iter()
                .filter(|member| typed_entries.iter().any(|(spn, _, _)| spn == *member))
                .for_each(|member| {
                    sb.push_str(format!(r#"  "{spn}" -> "{member}"{}"#, "\n").as_str());
                });
        }

        for (spn, uuid, obj_type) in typed_entries {
            let (color, shape, route) = match obj_type {
                ObjectType::Group => ("#b86367", "box", AdminRoute::ViewGroup { uuid }),
                ObjectType::BuiltinGroup => {
                    ("#8bc1d6", "component", AdminRoute::ViewGroup { uuid })
                }
                ObjectType::ServiceAccount => (
                    "#77c98d",
                    "parallelogram",
                    AdminRoute::ViewServiceAccount { uuid },
                ),
                ObjectType::Person => ("#af8bd6", "ellipse", AdminRoute::ViewPerson { uuid }),
            };
            let url = route.to_path();
            sb.push_str(
                format!(
                    r#"  "{spn}" [color = "{color}", shape = {shape}, URL = "{url}"]{}"#,
                    "\n"
                )
                .as_str(),
            );
        }
        sb.push('}');
        init_graphviz(sb.as_str());

        let node_refs = all::<ObjectType>()
            .map(|object_type: ObjectType| { (object_type, NodeRef::default()) })
            .collect::<Vec<_>>();

        let on_checkbox_click = {
            let scope = ctx.link().clone();
            let node_refs = node_refs.clone();
            move |_: Event| {
                let mut filters = vec![];

                for (obj_type, node_ref) in &node_refs {
                    if let Some(input_el) = node_ref.cast::<HtmlInputElement>() {
                        let checked = input_el.checked();

                        if checked {
                            filters.push(*obj_type);
                        }
                    }
                }
                scope.send_message(Msg::NewFilters { filters });
            }
        };

        let view_graph_source = {
            move |_: MouseEvent| {
                open_blank(sb.as_str());
            }
        };

        html! {
            <>
            <div class={CSS_PAGE_HEADER}>
            <h2>{ "ObjectGraph view" }</h2>
            </div>
            if entries.is_empty() {
                <div>
                  <h5>{ "No graph objects for the applied filters." }</h5>
                </div>
            } else {
                <div class="column">
                    <div class="hstack gap-3">
                    {
                        node_refs.iter().map(|(ot, node_ref)| {
                            let str = format!("{}", ot);
                            let selected = filters.contains(&ot);

                            html! {
                                <>
                                <div class="form-check">
                                  <input class="form-check-input obj-graph-filter-cb" type="checkbox" ref={ node_ref } id={str.clone()} onchange={on_checkbox_click.clone()} checked={selected}/>
                                  <label class="form-check-label" for={str.clone()}>{str.clone()}</label>
                                </div>
                                if *ot != ObjectType::last().unwrap() {
                                    <div class="vr"></div>
                                }
                                </>
                            }
                        }).collect::<Html>()
                    }
                    </div>
                    <button class="btn btn-primary mt-2" onclick={view_graph_source}>{ "View graph source" }</button>
                </div>
                <div id="graph-container" class="mt-3"></div>
            }
            </>
        }
    }

    fn view_error(&self, _ctx: &Context<Self>, msg: &str, kopid: Option<&str>) -> Html {
        error_page(msg, kopid)
    }

    async fn fetch_objects() -> Result<Msg, FetchError> {
        let urls = vec!["/v1/group", "/v1/service_account", "/v1/person"];
        let mut results = Vec::new();

        for url in urls {
            let (kopid, status, value, _) =
                do_request(url, RequestMethod::GET, None::<JsValue>).await?;
            results.push((kopid, status, value));
        }

        let mapped: Vec<_> = results
            .into_iter()
            .map(|(kopid, status, value)| {
                if status == 200 {
                    let entries: Vec<Entry> = serde_wasm_bindgen::from_value(value)
                        .expect_throw("Invalid response type - auth_init::AuthResponse");
                    Ok(entries)
                } else {
                    let emsg = value.as_string().unwrap_or_default();
                    Err(Msg::Error { emsg, kopid })
                }
            })
            .collect();

        let list_result: Result<Vec<Entry>, Msg> = mapped
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map(|v| v.into_iter().flatten().collect());

        match list_result {
            Ok(entries) => Ok(Msg::NewObjects { entries }),
            Err(e) => Ok(e),
        }
    }
}
