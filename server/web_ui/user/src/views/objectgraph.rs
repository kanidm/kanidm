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
use web_sys::{HtmlSelectElement};

use kanidm_proto::v1::Entry;
use kanidmd_web_ui_shared::utils::{init_graphviz};

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

pub struct ObjectGraphApp {
    state: State,
    filters: Vec<ObjectType>,
}

impl Component for ObjectGraphApp {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("views::objectgraph::create");

        ctx.link().send_future(async {
            Self::fetch_objects().await.unwrap_or_else(|v| v.into())
        });

        let state = State::Waiting;

        ObjectGraphApp { state, filters: vec![] }
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

impl ObjectGraphApp {
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

                // Logic to decide the type of each entry
                let obj_type = if classes.contains(&"group".to_string()) {
                    let uuid = entry.attrs.get("uuid")?.first()?;
                    // let description = entry.attrs.get("description").first();

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
                Some((name.clone(), obj_type))
            }).collect::<HashSet<(String, ObjectType)>>();

        // Vec<obj, obj's members>
        let members_of = entries.into_iter().filter_map(|entry| {
            let name = entry.attrs.get("name")?.first()?.clone();

            Some((name, entry.attrs.get("member")?.clone()))
        }).collect::<Vec<_>>();

        // Printing of the graph
        let mut sb = String::new();
        sb.push_str("digraph {\n  rankdir=\"RL\"\n");
        for (name, members) in members_of {
            members.iter()
                .map(|member| member.trim_end_matches("@localhost"))
                .filter(|member| typed_entries.iter().any(|(name, ot)| name == member))
                .for_each(|member| {
                    sb.push_str(format!("  {name} -> {member}\n").as_str());
                });
        }
        //
        // println!("  classDef groupClass fill:#f9f,stroke:#333,stroke-width:4px,stroke-dasharray: 5 5");
        // println!("  classDef builtInGroupClass fill:#bbf,stroke:#f66,stroke-width:2px,color:#fff,stroke-dasharray: 5 5");
        // println!("  classDef serviceAccountClass fill:#f9f,stroke:#333,stroke-width:4px");
        // println!("  classDef personClass fill:#bbf,stroke:#f66,stroke-width:2px,color:#fff");

        for (name, obj_type) in typed_entries {
            let attrs = match obj_type {
                ObjectType::Group => "color = \"#b86367\", shape = box",
                ObjectType::BuiltinGroup => "color = \"#8bc1d6\", shape = component",
                ObjectType::ServiceAccount => "color = \"#77c98d\", shape = parallelogram",
                ObjectType::Person => "color = \"#af8bd6\"",
            };
            sb.push_str(format!("  {name} [{attrs}]\n").as_str());
        }
        sb.push_str("}");
        init_graphviz(sb.as_str());

        let filter_selector_ref = NodeRef::default();

        let on_select_click = {
            let ref_clone = filter_selector_ref.clone();
            move |event: Event| {
                let selection = ref_clone.cast::<HtmlSelectElement>()
                    .expect("filter_selector_ref not bound to the select html elem")
                    .selected_options();
                console::debug!(&selection);
                let mut filters = vec![];
                for i in 0..*&selection.length() {
                    let option = selection.get_with_index(i)
                        .expect("couldnt get elem between 0 and selection length ???");
                    let attr = option.get_attribute("value").expect("Option missing an attribute named: value");
                    filters.push(ObjectType::try_from(attr).expect("Option attribute —value— is not a valid ObjectType"));
                }
                // console::debug!(&filters);
                ctx.link().send_message(Msg::NewFilters { filters });
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
                    <select class="custom-select" ref={filter_selector_ref} multiple=true onchange={on_select_click}>
                        {
                            all::<ObjectType>().map(|ot| {
                                let str = format!("{:?}", ot);
                                let selected = filters.contains(&ot);
                                html! {
                                    <option value={ str.clone() } selected={ selected }>{ str }</option>
                                }
                            }).collect::<Html>()
                        }
                    </select>
                    <pre class="codeblock">
                        <div id="graphsource"></div>
                    </pre>
                </div>
                <div id="graph-container"></div>
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
