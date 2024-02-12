use std::collections::HashSet;
use enum_iterator::{all, Sequence};
#[cfg(debug_assertions)]
use gloo::console;
use kanidmd_web_ui_shared::logo_img;
use yew::prelude::*;

use kanidmd_web_ui_shared::constants::{
    CSS_ALERT_DANGER, CSS_PAGE_HEADER, URL_USER_HOME,
};
use kanidmd_web_ui_shared::{do_request, error::FetchError, RequestMethod};
use wasm_bindgen::prelude::*;
use web_sys::{HtmlInputElement};
use yew_router::Routable;

use kanidm_proto::v1::Entry;
use kanidmd_web_ui_shared::utils::{document, init_graphviz, open_blank, window};
use crate::router::AdminRoute;

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

#[derive(Clone, Debug)]
pub enum GraphType {
    Graphviz,
    Mermaid,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Sequence)]
pub enum ObjectType {
    Group,
    BuiltinGroup,
    ServiceAccount,
    Person,
}

impl TryFrom<String> for ObjectType {

    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        return all::<ObjectType>().find(|x| format!("{x:?}") == value).ok_or(())
    }
}

impl ObjectType {
    fn ui_str(self: Self) -> String {
        format!("{:?}", self)
    }
}

pub enum State {
    Waiting,
    Rendering,
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

        ctx.link().send_future(async {
            Self::fetch_objects().await.unwrap_or_else(|v| v.into())
        });

        let state = State::Waiting;

        AdminObjectGraph { state, filters: vec![] }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::objectgraph::update");
        match msg {
            Msg::NewObjects { entries } => {
                console::debug!("Waiter waiter new objects arriveth");
                self.state = State::Ready { entries }
            }
            Msg::NewFilters { filters } => {
                console::debug!("Waiter waiter new filters arriveth");
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
            State::Rendering => self.view_waiting()
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("views::objectgraph::rendered");
    }
}

impl AdminObjectGraph {
    fn view_waiting(&self) -> Html {
        html! {
            <>
              <div class="vert-center">
                <div class="spinner-border text-dark" role="status">
                  <span class="visually-hidden">{ "Loading..." }</span>
                </div>
              </div>
            </>
        }
    }

    fn view_ready(&self, ctx: &Context<Self>, filters: &Vec<ObjectType>, entries: &Vec<Entry>) -> Html {
        // Please help me, I don't know how to make a grid look nice 🥺
        let typed_entries = entries.iter()
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

                // filter out the things we want to keep, if the filter is empty we assume we want all.
                if !filters.contains(&obj_type) && !filters.is_empty() {
                    return None;
                }

                let name = entry.attrs.get("name")?.first()?;
                Some((name.clone(), uuid.clone(), obj_type))
            }).collect::<HashSet<(String, String, ObjectType)>>();

        // Vec<obj, obj's members>
        let members_of = entries.into_iter().filter_map(|entry| {
            let name = entry.attrs.get("name")?.first()?.clone();
            let uuid = entry.attrs.get("uuid")?.first()?.clone();
            let keep = typed_entries.iter().any(|(_, filtered_uuid, _)| { &uuid == filtered_uuid });
            if keep {
                Some((name, uuid, entry.attrs.get("member")?.clone()))
            } else {
                None
            }
        }).collect::<Vec<_>>();

        // Printing of the graph
        let mut sb = String::new();
        sb.push_str("digraph {\n  rankdir=\"RL\"\n");
        for (name, uuid, members) in members_of {
            members.iter()
                .map(|member| member.trim_end_matches("@localhost"))
                .filter(|member| typed_entries.iter().any(|(name, uuid, ot)| name == member))
                .for_each(|member| {
                    sb.push_str(format!("  {name} -> {member}\n").as_str());
                });
        }

        for (name, uuid, obj_type) in typed_entries {
            let (color, shape, route) = match obj_type {
                ObjectType::Group => ("#b86367", "box", AdminRoute::ViewGroup { uuid }),
                ObjectType::BuiltinGroup => ("#8bc1d6", "component", AdminRoute::ViewGroup { uuid }),
                ObjectType::ServiceAccount => ("#77c98d", "parallelogram", AdminRoute::ViewServiceAccount { uuid }),
                ObjectType::Person => ("#af8bd6", "ellipse", AdminRoute::ViewPerson { uuid }),
            };
            let url = route.to_path();
            sb.push_str(format!(r#"  {name} [color = "{color}", shape = {shape}, URL = "{url}"]{}"#, "\n").as_str());
        }
        sb.push_str("}");
        init_graphviz(&sb.as_str());

        let filter_selector_ref = NodeRef::default();

        let on_checkbox_click = {
            let scope = ctx.link().clone();
            move |event: Event| {
                let coll = document().get_elements_by_class_name("obj-graph-filter-cb");
                let mut filters = vec![];

                for i in 0..*&coll.length() {
                    let option = coll.get_with_index(i)
                        .expect("couldnt get elem between 0 and selection length ???");
                    let input_el = option.unchecked_into::<HtmlInputElement>();
                    let checked = input_el.checked();

                    if checked {
                        let value = input_el.id();
                        let obj_type = ObjectType::try_from(value).expect("Option attribute —value— is not a valid ObjectType");
                        filters.push(obj_type);
                    }
                }
                scope.send_message(Msg::NewFilters { filters });
            }
        };

        let view_graph_source = {
            move |e: MouseEvent| {
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
                        all::<ObjectType>().map(|ot| {
                            let str = format!("{:?}", ot);
                            let selected = filters.contains(&ot);
                            html! {
                                <>
                                <div class="form-check">
                                  <input class="form-check-input obj-graph-filter-cb" type="checkbox" id={str.clone()} onchange={on_checkbox_click.clone()} checked={selected}/>
                                  <label class="form-check-label" for={str.clone()}>{str.clone()}</label>
                                </div>
                                if ot != ObjectType::last().unwrap() {
                                    <div class="vr"></div>
                                }
                                </>
                            }
                        }).collect::<Html>()
                    }
                    </div>
                    <button class="btn btn-primary" onclick={view_graph_source}>{ "View graph source" }</button>
                </div>
                <div id="graph-container" class="mt-3"></div>
            }
            </>
        }
    }

    fn view_error(&self, _ctx: &Context<Self>, msg: &str, kopid: Option<&str>) -> Html {
        html! {
          <>
            <p class="text-center">
                {logo_img()}
            </p>
            <div class={CSS_ALERT_DANGER} role="alert">
              <h2>{ "An Error Occurred 🥺" }</h2>
            <p>{ msg.to_string() }</p>
            <p>
                {
                    if let Some(opid) = kopid.as_ref() {
                        format!("Operation ID: {}", opid)
                    } else {
                        "Local Error".to_string()
                    }
                }
            </p>
            </div>
            <p class="text-center">
              <a href={URL_USER_HOME}><button href={URL_USER_HOME} class="btn btn-secondary" aria-label="Return home">{"Return to the home page"}</button></a>
            </p>
          </>
        }
    }

    async fn fetch_objects() -> Result<Msg, FetchError> {
        let urls = vec!["/v1/group", "/v1/service_account", "/v1/person"];
        let mut results = Vec::new();

        for url in urls {
            let (kopid, status, value, _) = do_request(url, RequestMethod::GET, None::<JsValue>).await?;
            results.push((kopid, status, value));
        }

        let mapped: Vec<_> = results.into_iter().map(|(kopid, status, value)| {
            if status == 200 {
                let entries: Vec<Entry> = serde_wasm_bindgen::from_value(value)
                    .expect_throw("Invalid response type - auth_init::AuthResponse");
                Ok(entries)
            } else {
                let emsg = value.as_string().unwrap_or_default();
                Err(Msg::Error { emsg, kopid })
            }
        }).collect();

        let list_result: Result<Vec<Entry>, Msg> = mapped
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map(|v| { v.into_iter().flatten().collect() });

        match list_result {
            Ok(entries) => Ok(Msg::NewObjects { entries }),
            Err(e) => Ok(e)
        }
    }
}
