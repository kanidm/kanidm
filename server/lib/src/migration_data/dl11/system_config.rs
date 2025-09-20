use crate::constants::uuids::*;

use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::prelude::{Attribute, EntryClass};
use crate::value::Value;

// Default entries for system_config
// This is separated because the password badlist section may become very long

lazy_static! {
    pub static ref E_SYSTEM_INFO_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::SystemInfo.to_value()),
        (Attribute::Class, EntryClass::System.to_value()),
        (Attribute::Uuid, Value::Uuid(UUID_SYSTEM_INFO)),
        (
            Attribute::Description,
            Value::new_utf8s("System (local) info and metadata object.")
        ),
        (Attribute::Version, Value::Uint32(20))
    );
    pub static ref E_DOMAIN_INFO_DL6: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::DomainInfo.to_value()),
        (Attribute::Class, EntryClass::System.to_value()),
        (Attribute::Class, EntryClass::KeyObject.to_value()),
        (Attribute::Class, EntryClass::KeyObjectJwtEs256.to_value()),
        (Attribute::Class, EntryClass::KeyObjectJweA128GCM.to_value()),
        (Attribute::Name, Value::new_iname("domain_local")),
        (Attribute::Uuid, Value::Uuid(UUID_DOMAIN_INFO)),
        (
            Attribute::Description,
            Value::new_utf8s("This local domain's info and metadata object.")
        )
    );
    pub static ref E_SYSTEM_CONFIG_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::SystemConfig.to_value()),
        (Attribute::Class, EntryClass::System.to_value()),
        (Attribute::Uuid, Value::Uuid(UUID_SYSTEM_CONFIG)),
        (
            Attribute::Description,
            Value::new_utf8s("System (replicated) configuration options.")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("bad@no3IBTyqHu$list")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8(
                "demo_badlist_shohfie3aeci2oobur0aru9uushah6EiPi2woh4hohngoighaiRuepieN3ongoo1"
            )
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("100preteamare")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("14defebrero")),
        (Attribute::BadlistPassword, Value::new_iutf8("1life1love")),
        (Attribute::BadlistPassword, Value::new_iutf8("1life2live")),
        (Attribute::BadlistPassword, Value::new_iutf8("1love1life")),
        (Attribute::BadlistPassword, Value::new_iutf8("1love4life")),
        (Attribute::BadlistPassword, Value::new_iutf8("212224236248")),
        (Attribute::BadlistPassword, Value::new_iutf8("2813308004")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("2fast2furious")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("2gether4ever")),
        (Attribute::BadlistPassword, Value::new_iutf8("2pacshakur")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("30secondstomars")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("3doorsdown")),
        (Attribute::BadlistPassword, Value::new_iutf8("6cyclemind")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("<div><embed src=\\")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("@hotmail.com")),
        (Attribute::BadlistPassword, Value::new_iutf8("@yahoo.com")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("Lets you update your FunNotes and more!")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("TEQUIEROMUCHO")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("TEXT ONLY AD")),
        (Attribute::BadlistPassword, Value::new_iutf8("abretesesamo")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("administrador")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("aeropostale")),
        (Attribute::BadlistPassword, Value::new_iutf8("akinkalang")),
        (Attribute::BadlistPassword, Value::new_iutf8("akucintakamu")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("akusayangkamu")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("alfayomega")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("alhamdulillah")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("allaboutme")),
        (Attribute::BadlistPassword, Value::new_iutf8("allahuakbar")),
        (Attribute::BadlistPassword, Value::new_iutf8("alleyesonme")),
        (Attribute::BadlistPassword, Value::new_iutf8("alquimista")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("alwaysandforever")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("amarteduele")),
        (Attribute::BadlistPassword, Value::new_iutf8("amigas4ever")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("amigasporsiempre")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("amigasx100pre")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("amigasxsiempre")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("amoamifamilia")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("amordelbueno")),
        (Attribute::BadlistPassword, Value::new_iutf8("amordemivida")),
        (Attribute::BadlistPassword, Value::new_iutf8("amoresperros")),
        (Attribute::BadlistPassword, Value::new_iutf8("amoreterno")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("amorimposible")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("amorporsiempre")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("amorprohibido")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("amorverdadero")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("amotemuito")),
        (Attribute::BadlistPassword, Value::new_iutf8("anaranjado")),
        (Attribute::BadlistPassword, Value::new_iutf8("angeldeamor")),
        (Attribute::BadlistPassword, Value::new_iutf8("angellocsin")),
        (Attribute::BadlistPassword, Value::new_iutf8("angelofdeath")),
        (Attribute::BadlistPassword, Value::new_iutf8("anggandako")),
        (Attribute::BadlistPassword, Value::new_iutf8("aniversario")),
        (Attribute::BadlistPassword, Value::new_iutf8("apaixonada")),
        (Attribute::BadlistPassword, Value::new_iutf8("apocalipsa")),
        (Attribute::BadlistPassword, Value::new_iutf8("apocalipse")),
        (Attribute::BadlistPassword, Value::new_iutf8("apocalipsis")),
        (Attribute::BadlistPassword, Value::new_iutf8("apolinario")),
        (Attribute::BadlistPassword, Value::new_iutf8("arquitectura")),
        (Attribute::BadlistPassword, Value::new_iutf8("arrolladora")),
        (Attribute::BadlistPassword, Value::new_iutf8("asieslavida")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("assalamualaikum")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("auxiliadora")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("avengedsevenfold")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("ayamgoreng")),
        (Attribute::BadlistPassword, Value::new_iutf8("babasonicos")),
        (Attribute::BadlistPassword, Value::new_iutf8("balla4life")),
        (Attribute::BadlistPassword, Value::new_iutf8("barriofino")),
        (Attribute::BadlistPassword, Value::new_iutf8("bball4life")),
        (Attribute::BadlistPassword, Value::new_iutf8("bebitalinda")),
        (Attribute::BadlistPassword, Value::new_iutf8("bellissima")),
        (Attribute::BadlistPassword, Value::new_iutf8("bendiciones")),
        (Attribute::BadlistPassword, Value::new_iutf8("benfiquista")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("bestfriends4ever")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("bestfriendsforever")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("bienvenido")),
        (Attribute::BadlistPassword, Value::new_iutf8("billandben")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("blackandwhite")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("blackeyedpeas")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("bobesponja")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("bobthebuilder")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("bomboncito")),
        (Attribute::BadlistPassword, Value::new_iutf8("borreguito")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("boysoverflowers")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("bringmetolife")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("bustitbaby")),
        (Attribute::BadlistPassword, Value::new_iutf8("cachorrita")),
        (Attribute::BadlistPassword, Value::new_iutf8("cachorrito")),
        (Attribute::BadlistPassword, Value::new_iutf8("cafetacuba")),
        (Attribute::BadlistPassword, Value::new_iutf8("calculadora")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("californication")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("camiloteamo")),
        (Attribute::BadlistPassword, Value::new_iutf8("candyland1")),
        (Attribute::BadlistPassword, Value::new_iutf8("candyshop1")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("canttouchthis")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("caperucita")),
        (Attribute::BadlistPassword, Value::new_iutf8("caprichosa")),
        (Attribute::BadlistPassword, Value::new_iutf8("caradeperro")),
        (Attribute::BadlistPassword, Value::new_iutf8("caranguejo")),
        (Attribute::BadlistPassword, Value::new_iutf8("caricatura")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("caritadeangel")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("carteldesanta")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("castravete")),
        (Attribute::BadlistPassword, Value::new_iutf8("catinthehat")),
        (Attribute::BadlistPassword, Value::new_iutf8("catsanddogs")),
        (Attribute::BadlistPassword, Value::new_iutf8("celticfc1888")),
        (Attribute::BadlistPassword, Value::new_iutf8("cenicienta")),
        (Attribute::BadlistPassword, Value::new_iutf8("chaparrita")),
        (Attribute::BadlistPassword, Value::new_iutf8("chaparrito")),
        (Attribute::BadlistPassword, Value::new_iutf8("charolastra")),
        (Attribute::BadlistPassword, Value::new_iutf8("chicafresa")),
        (Attribute::BadlistPassword, Value::new_iutf8("chikistrikis")),
        (Attribute::BadlistPassword, Value::new_iutf8("chilindrina")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("chingatumadre")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("chiquititas")),
        (Attribute::BadlistPassword, Value::new_iutf8("chocoholic")),
        (Attribute::BadlistPassword, Value::new_iutf8("chris brown")),
        (Attribute::BadlistPassword, Value::new_iutf8("chupachups")),
        (Attribute::BadlistPassword, Value::new_iutf8("cintasejati")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2004")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2005")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2006")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2007")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2008")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2009")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2010")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2011")),
        (Attribute::BadlistPassword, Value::new_iutf8("classof2012")),
        (Attribute::BadlistPassword, Value::new_iutf8("computacion")),
        (Attribute::BadlistPassword, Value::new_iutf8("comunicacion")),
        (Attribute::BadlistPassword, Value::new_iutf8("confidencial")),
        (Attribute::BadlistPassword, Value::new_iutf8("contabilidad")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("cookiesncream")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("corazondemelon")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("cositarica")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("cradleoffilth")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("crazysexycool")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("crepusculo")),
        (Attribute::BadlistPassword, Value::new_iutf8("crisostomo")),
        (Attribute::BadlistPassword, Value::new_iutf8("cristomeama")),
        (Attribute::BadlistPassword, Value::new_iutf8("cristoteama")),
        (Attribute::BadlistPassword, Value::new_iutf8("cristoteamo")),
        (Attribute::BadlistPassword, Value::new_iutf8("cristovive")),
        (Attribute::BadlistPassword, Value::new_iutf8("cualquiera")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("cualquiercosa")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("cuchurrumin")),
        (Attribute::BadlistPassword, Value::new_iutf8("cymruambyth")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("daddyslilgirl")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("daddyslittlegirl")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("danitykane")),
        (Attribute::BadlistPassword, Value::new_iutf8("daveyhavok")),
        (Attribute::BadlistPassword, Value::new_iutf8("dcshoecousa")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("deportivocali")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("depredador")),
        (Attribute::BadlistPassword, Value::new_iutf8("desiderata")),
        (Attribute::BadlistPassword, Value::new_iutf8("dgenerationx")),
        (Attribute::BadlistPassword, Value::new_iutf8("dimmuborgir")),
        (Attribute::BadlistPassword, Value::new_iutf8("diosesbueno")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("diostebendiga")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("divalicious")),
        (Attribute::BadlistPassword, Value::new_iutf8("dolcegabbana")),
        (Attribute::BadlistPassword, Value::new_iutf8("dracomalfoy")),
        (Attribute::BadlistPassword, Value::new_iutf8("dragosteamea")),
        (Attribute::BadlistPassword, Value::new_iutf8("eatmyshorts")),
        (Attribute::BadlistPassword, Value::new_iutf8("ecuatoriana")),
        (Attribute::BadlistPassword, Value::new_iutf8("elamorapesta")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("elamordemivida")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("elamorduele")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("elamornoexiste")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("emperatriz")),
        (Attribute::BadlistPassword, Value::new_iutf8("encantadia")),
        (Attribute::BadlistPassword, Value::new_iutf8("enfermagem")),
        (Attribute::BadlistPassword, Value::new_iutf8("enfermeria")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("ereselamordemivida")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("ereslomaximo")),
        (Attribute::BadlistPassword, Value::new_iutf8("ereslomejor")),
        (Attribute::BadlistPassword, Value::new_iutf8("eresmiamor")),
        (Attribute::BadlistPassword, Value::new_iutf8("eresmivida")),
        (Attribute::BadlistPassword, Value::new_iutf8("escritorio")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("espiritusanto")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("estadosunidos")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("estrelinha")),
        (Attribute::BadlistPassword, Value::new_iutf8("estudiante")),
        (Attribute::BadlistPassword, Value::new_iutf8("ewankosayo")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("extraterrestre")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("eyeshield21")),
        (Attribute::BadlistPassword, Value::new_iutf8("fadetoblack")),
        (Attribute::BadlistPassword, Value::new_iutf8("fergalicious")),
        (Attribute::BadlistPassword, Value::new_iutf8("figueiredo")),
        (Attribute::BadlistPassword, Value::new_iutf8("filadelfia")),
        (Attribute::BadlistPassword, Value::new_iutf8("finisterra")),
        (Attribute::BadlistPassword, Value::new_iutf8("fishandchips")),
        (Attribute::BadlistPassword, Value::new_iutf8("flordeliza")),
        (Attribute::BadlistPassword, Value::new_iutf8("flordeloto")),
        (Attribute::BadlistPassword, Value::new_iutf8("floricienta")),
        (Attribute::BadlistPassword, Value::new_iutf8("florinsalam")),
        (Attribute::BadlistPassword, Value::new_iutf8("floripondia")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("foreverandever")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("frangipani")),
        (Attribute::BadlistPassword, Value::new_iutf8("free2rhyme")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("fresasconcrema")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("frootloops")),
        (Attribute::BadlistPassword, Value::new_iutf8("fuckevery1")),
        (Attribute::BadlistPassword, Value::new_iutf8("fuckthepope")),
        (Attribute::BadlistPassword, Value::new_iutf8("funinthesun")),
        (Attribute::BadlistPassword, Value::new_iutf8("funkymunky")),
        (Attribute::BadlistPassword, Value::new_iutf8("fushigiyugi")),
        (Attribute::BadlistPassword, Value::new_iutf8("fushigiyuugi")),
        (Attribute::BadlistPassword, Value::new_iutf8("gastronomia")),
        (Attribute::BadlistPassword, Value::new_iutf8("gatitolindo")),
        (Attribute::BadlistPassword, Value::new_iutf8("gearsofwar")),
        (Attribute::BadlistPassword, Value::new_iutf8("gettherefast")),
        (Attribute::BadlistPassword, Value::new_iutf8("girlygirl1")),
        (Attribute::BadlistPassword, Value::new_iutf8("glorytogod")),
        (Attribute::BadlistPassword, Value::new_iutf8("godschild1")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("gofuckyourself")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("goody2shoes")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("grandtheftauto")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("grenouille")),
        (Attribute::BadlistPassword, Value::new_iutf8("gryffindor")),
        (Attribute::BadlistPassword, Value::new_iutf8("gummybear1")),
        (Attribute::BadlistPassword, Value::new_iutf8("gunsandroses")),
        (Attribute::BadlistPassword, Value::new_iutf8("gunsnroses")),
        (Attribute::BadlistPassword, Value::new_iutf8("habbohotel")),
        (Attribute::BadlistPassword, Value::new_iutf8("hakunamatata")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("hannah montana")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("happygolucky")),
        (Attribute::BadlistPassword, Value::new_iutf8("harry potter")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("hateitorloveit")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("haveaniceday")),
        (Attribute::BadlistPassword, Value::new_iutf8("hello kitty")),
        (Attribute::BadlistPassword, Value::new_iutf8("hindikoalam")),
        (Attribute::BadlistPassword, Value::new_iutf8("hipopotamo")),
        (Attribute::BadlistPassword, Value::new_iutf8("hocuspocus")),
        (Attribute::BadlistPassword, Value::new_iutf8("holaatodos")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("holacomoestas")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("holaquetal")),
        (Attribute::BadlistPassword, Value::new_iutf8("hollaback1")),
        (Attribute::BadlistPassword, Value::new_iutf8("homeandaway")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("homesweethome")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("hoobastank")),
        (Attribute::BadlistPassword, Value::new_iutf8("hotandsexy")),
        (Attribute::BadlistPassword, Value::new_iutf8("hotmail.com")),
        (Attribute::BadlistPassword, Value::new_iutf8("hotmail123")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("hugsandkisses")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("hugsnkisses")),
        (Attribute::BadlistPassword, Value::new_iutf8("hunnibunni")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("hunterxhunter")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("i love you")),
        (Attribute::BadlistPassword, Value::new_iutf8("i.love.you")),
        (Attribute::BadlistPassword, Value::new_iutf8("i_love_you")),
        (Attribute::BadlistPassword, Value::new_iutf8("iamwhatiam")),
        (Attribute::BadlistPassword, Value::new_iutf8("ichliebedich")),
        (Attribute::BadlistPassword, Value::new_iutf8("idontloveyou")),
        (Attribute::BadlistPassword, Value::new_iutf8("ihatelife1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ihatemylife")),
        (Attribute::BadlistPassword, Value::new_iutf8("ihave3kids")),
        (Attribute::BadlistPassword, Value::new_iutf8("iheartyou!")),
        (Attribute::BadlistPassword, Value::new_iutf8("iheartyou1")),
        (Attribute::BadlistPassword, Value::new_iutf8("iheartyou2")),
        (Attribute::BadlistPassword, Value::new_iutf8("ikawlamang")),
        (Attribute::BadlistPassword, Value::new_iutf8("ikhouvanjou")),
        (Attribute::BadlistPassword, Value::new_iutf8("illnevertell")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilove2dance")),
        (Attribute::BadlistPassword, Value::new_iutf8("iloveboys!")),
        (Attribute::BadlistPassword, Value::new_iutf8("iloveboys1")),
        (Attribute::BadlistPassword, Value::new_iutf8("iloveboys2")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("ilovechrisbrown")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovecody1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovedogs1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovejake1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovejose1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovejosh!")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovejosh1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovekyle1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemike!")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemyboo")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemycat")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemydad")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemydaddy")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemydog")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("ilovemyfriends")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemymom")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemymommy")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemymum")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemymummy")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("ilovemysister")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovemyson")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("ilovenickjonas")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovenoone")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovepink1")),
        (Attribute::BadlistPassword, Value::new_iutf8("iloveryan!")),
        (Attribute::BadlistPassword, Value::new_iutf8("iloveryan1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovesome1")),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovethelord")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("ilovethisgame")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("ilovetodance")),
        (Attribute::BadlistPassword, Value::new_iutf8("iloveusomuch")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("iloveyousomuch")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("ilovezacefron")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("iluv2dance")),
        (Attribute::BadlistPassword, Value::new_iutf8("iluvu4ever")),
        (Attribute::BadlistPassword, Value::new_iutf8("imprimanta")),
        (Attribute::BadlistPassword, Value::new_iutf8("imthebest1")),
        (Attribute::BadlistPassword, Value::new_iutf8("inalcanzable")),
        (Attribute::BadlistPassword, Value::new_iutf8("indragostita")),
        (Attribute::BadlistPassword, Value::new_iutf8("inframundo")),
        (Attribute::BadlistPassword, Value::new_iutf8("inglaterra")),
        (Attribute::BadlistPassword, Value::new_iutf8("ingoditrust")),
        (Attribute::BadlistPassword, Value::new_iutf8("inmaculada")),
        (Attribute::BadlistPassword, Value::new_iutf8("inolvidable")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("insaneclownposse")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("inspiracion")),
        (Attribute::BadlistPassword, Value::new_iutf8("inteligencia")),
        (Attribute::BadlistPassword, Value::new_iutf8("inteligente")),
        (Attribute::BadlistPassword, Value::new_iutf8("invu4uraqt")),
        (Attribute::BadlistPassword, Value::new_iutf8("ioriyagami")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("itsallaboutme")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("iubireamea")),
        (Attribute::BadlistPassword, Value::new_iutf8("iwillsurvive")),
        (Attribute::BadlistPassword, Value::new_iutf8("jabbawockeez")),
        (Attribute::BadlistPassword, Value::new_iutf8("jackandjill")),
        (Attribute::BadlistPassword, Value::new_iutf8("jamiroquai")),
        (Attribute::BadlistPassword, Value::new_iutf8("jensenackles")),
        (Attribute::BadlistPassword, Value::new_iutf8("jesusesamor")),
        (Attribute::BadlistPassword, Value::new_iutf8("jigglypuff")),
        (Attribute::BadlistPassword, Value::new_iutf8("joeyjordison")),
        (Attribute::BadlistPassword, Value::new_iutf8("jogabonito")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("jonas brothers")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("joshgroban")),
        (Attribute::BadlistPassword, Value::new_iutf8("juggalette")),
        (Attribute::BadlistPassword, Value::new_iutf8("kagandahan")),
        (Attribute::BadlistPassword, Value::new_iutf8("kaleidostar")),
        (Attribute::BadlistPassword, Value::new_iutf8("keepitreal")),
        (Attribute::BadlistPassword, Value::new_iutf8("keteimporta")),
        (Attribute::BadlistPassword, Value::new_iutf8("kilometros")),
        (Attribute::BadlistPassword, Value::new_iutf8("kimsamsoon")),
        (Attribute::BadlistPassword, Value::new_iutf8("kingofkings")),
        (Attribute::BadlistPassword, Value::new_iutf8("kmzwa8awaa")),
        (Attribute::BadlistPassword, Value::new_iutf8("kumbiakings")),
        (Attribute::BadlistPassword, Value::new_iutf8("kuvhlubkoj")),
        (Attribute::BadlistPassword, Value::new_iutf8("lacramioara")),
        (Attribute::BadlistPassword, Value::new_iutf8("lacunacoil")),
        (Attribute::BadlistPassword, Value::new_iutf8("laffytaffy")),
        (Attribute::BadlistPassword, Value::new_iutf8("lamaravilla")),
        (Attribute::BadlistPassword, Value::new_iutf8("lamashermosa")),
        (Attribute::BadlistPassword, Value::new_iutf8("laprincesita")),
        (Attribute::BadlistPassword, Value::new_iutf8("larcenciel")),
        (Attribute::BadlistPassword, Value::new_iutf8("lasdivinas")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("lavidaesbella")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("lavidaloca")),
        (Attribute::BadlistPassword, Value::new_iutf8("leedongwook")),
        (Attribute::BadlistPassword, Value::new_iutf8("leothelion")),
        (Attribute::BadlistPassword, Value::new_iutf8("licenciada")),
        (Attribute::BadlistPassword, Value::new_iutf8("lifegoeson")),
        (Attribute::BadlistPassword, Value::new_iutf8("lifesabitch")),
        (Attribute::BadlistPassword, Value::new_iutf8("linkin park")),
        (Attribute::BadlistPassword, Value::new_iutf8("lipgloss12")),
        (Attribute::BadlistPassword, Value::new_iutf8("literatura")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("livelaughlove")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("livelovelaugh")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("liveyourlife")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("lordoftherings")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("loserface1")),
        (Attribute::BadlistPassword, Value::new_iutf8("losmejores")),
        (Attribute::BadlistPassword, Value::new_iutf8("lotsoflove")),
        (Attribute::BadlistPassword, Value::new_iutf8("loveandhate")),
        (Attribute::BadlistPassword, Value::new_iutf8("loveandpeace")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("loveisintheair")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("lovemeorhateme")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("lovenkrands")),
        (Attribute::BadlistPassword, Value::new_iutf8("loveofmylife")),
        (Attribute::BadlistPassword, Value::new_iutf8("loveorhate")),
        (Attribute::BadlistPassword, Value::new_iutf8("lovetolove")),
        (Attribute::BadlistPassword, Value::new_iutf8("loveu4ever")),
        (Attribute::BadlistPassword, Value::new_iutf8("loveydovey")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("loveyousomuch")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("luciernaga")),
        (Attribute::BadlistPassword, Value::new_iutf8("luvme4ever")),
        (Attribute::BadlistPassword, Value::new_iutf8("luzviminda")),
        (Attribute::BadlistPassword, Value::new_iutf8("machupichu")),
        (Attribute::BadlistPassword, Value::new_iutf8("madalinutza")),
        (Attribute::BadlistPassword, Value::new_iutf8("mahal kita")),
        (Attribute::BadlistPassword, Value::new_iutf8("mahalkokayo")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("mahalnamahalkita")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("makedonija")),
        (Attribute::BadlistPassword, Value::new_iutf8("mamichula1")),
        (Attribute::BadlistPassword, Value::new_iutf8("mapagmahal")),
        (Attribute::BadlistPassword, Value::new_iutf8("maravillosa")),
        (Attribute::BadlistPassword, Value::new_iutf8("maravilloso")),
        (Attribute::BadlistPassword, Value::new_iutf8("mardecopas")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("mariadelcarmen")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("matrimonio")),
        (Attribute::BadlistPassword, Value::new_iutf8("meamomucho")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("mejoresamigas")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("memyselfandi")),
        (Attribute::BadlistPassword, Value::new_iutf8("meneketehe")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("mequieromucho")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("mercadotecnia")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("metamorfosis")),
        (Attribute::BadlistPassword, Value::new_iutf8("miamorerestu")),
        (Attribute::BadlistPassword, Value::new_iutf8("miamorteamo")),
        (Attribute::BadlistPassword, Value::new_iutf8("mikeshinoda")),
        (Attribute::BadlistPassword, Value::new_iutf8("milagritos")),
        (Attribute::BadlistPassword, Value::new_iutf8("millonarios")),
        (Attribute::BadlistPassword, Value::new_iutf8("mimamamemima")),
        (Attribute::BadlistPassword, Value::new_iutf8("mimejoramiga")),
        (Attribute::BadlistPassword, Value::new_iutf8("mirmodepon")),
        (Attribute::BadlistPassword, Value::new_iutf8("mis3amores")),
        (Attribute::BadlistPassword, Value::new_iutf8("misdosamores")),
        (Attribute::BadlistPassword, Value::new_iutf8("misericordia")),
        (Attribute::BadlistPassword, Value::new_iutf8("missthang1")),
        (Attribute::BadlistPassword, Value::new_iutf8("miunicoamor")),
        (Attribute::BadlistPassword, Value::new_iutf8("mividaerestu")),
        (Attribute::BadlistPassword, Value::new_iutf8("mividaloca")),
        (Attribute::BadlistPassword, Value::new_iutf8("mommasgirl")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("mommyanddaddy")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("monserrath")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("morethanwords")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("moscraciun")),
        (Attribute::BadlistPassword, Value::new_iutf8("moulinrouge")),
        (Attribute::BadlistPassword, Value::new_iutf8("msnhotmail")),
        (Attribute::BadlistPassword, Value::new_iutf8("muiesteaua")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("mummyanddaddy")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("mummysgirl")),
        (Attribute::BadlistPassword, Value::new_iutf8("musicislife")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("musicismylife")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("muthafucka")),
        (Attribute::BadlistPassword, Value::new_iutf8("muñequita")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("mychemicalromance")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("mylittlepony")),
        (Attribute::BadlistPassword, Value::new_iutf8("myonlylove")),
        (Attribute::BadlistPassword, Value::new_iutf8("myslideshow")),
        (Attribute::BadlistPassword, Value::new_iutf8("myspace.com")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("nabucodonosor")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("nascimento")),
        (Attribute::BadlistPassword, Value::new_iutf8("nasigoreng")),
        (Attribute::BadlistPassword, Value::new_iutf8("nebunatica")),
        (Attribute::BadlistPassword, Value::new_iutf8("nepomuceno")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("neversaynever")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("nick jonas")),
        (Attribute::BadlistPassword, Value::new_iutf8("nickjonas1")),
        (Attribute::BadlistPassword, Value::new_iutf8("nistelrooy")),
        (Attribute::BadlistPassword, Value::new_iutf8("nomeacuerdo")),
        (Attribute::BadlistPassword, Value::new_iutf8("nomeolvides")),
        (Attribute::BadlistPassword, Value::new_iutf8("nosequeponer")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("nuncateolvidare")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("nymphetamine")),
        (Attribute::BadlistPassword, Value::new_iutf8("odontologia")),
        (Attribute::BadlistPassword, Value::new_iutf8("ojosverdes")),
        (Attribute::BadlistPassword, Value::new_iutf8("oneandonly")),
        (Attribute::BadlistPassword, Value::new_iutf8("oneofakind")),
        (Attribute::BadlistPassword, Value::new_iutf8("onetreehill")),
        (Attribute::BadlistPassword, Value::new_iutf8("onomatopoeia")),
        (Attribute::BadlistPassword, Value::new_iutf8("ositolindo")),
        (Attribute::BadlistPassword, Value::new_iutf8("ositopanda")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("padrinosmagicos")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("painislove")),
        (Attribute::BadlistPassword, Value::new_iutf8("pandalandia")),
        (Attribute::BadlistPassword, Value::new_iutf8("panganiban")),
        (Attribute::BadlistPassword, Value::new_iutf8("pangilinan")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("panicatthedisco")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("pantelimon")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("paralelepipedo")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("paralelipiped")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("parasiempre")),
        (Attribute::BadlistPassword, Value::new_iutf8("pasawayako")),
        (Attribute::BadlistPassword, Value::new_iutf8("pasodeblas")),
        (Attribute::BadlistPassword, Value::new_iutf8("peace&love")),
        (Attribute::BadlistPassword, Value::new_iutf8("peaceandlove")),
        (Attribute::BadlistPassword, Value::new_iutf8("periwinkle")),
        (Attribute::BadlistPassword, Value::new_iutf8("petewentz1")),
        (Attribute::BadlistPassword, Value::new_iutf8("pimpmyride")),
        (Attribute::BadlistPassword, Value::new_iutf8("pinkaholic")),
        (Attribute::BadlistPassword, Value::new_iutf8("pinkandblue")),
        (Attribute::BadlistPassword, Value::new_iutf8("playa4life")),
        (Attribute::BadlistPassword, Value::new_iutf8("policarpio")),
        (Attribute::BadlistPassword, Value::new_iutf8("politecnico")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("praisethelord")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("prettyinpink")),
        (Attribute::BadlistPassword, Value::new_iutf8("prostituta")),
        (Attribute::BadlistPassword, Value::new_iutf8("psicologia")),
        (Attribute::BadlistPassword, Value::new_iutf8("psihologie")),
        (Attribute::BadlistPassword, Value::new_iutf8("puccaygaru")),
        (Attribute::BadlistPassword, Value::new_iutf8("punknotdead")),
        (Attribute::BadlistPassword, Value::new_iutf8("pussinboots")),
        (Attribute::BadlistPassword, Value::new_iutf8("queteimporta")),
        (Attribute::BadlistPassword, Value::new_iutf8("quetzalcoatl")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("qwertyuiopasdfghjklzxcvbnm")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("recuerdame")),
        (Attribute::BadlistPassword, Value::new_iutf8("resistencia")),
        (Attribute::BadlistPassword, Value::new_iutf8("restinpeace")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("reymisterio619")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("reymysterio619")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("ricardoarjona")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("romeoyjulieta")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("rosesarered")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("rositafresita")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("rupertgrint")),
        (Attribute::BadlistPassword, Value::new_iutf8("ryansheckler")),
        (Attribute::BadlistPassword, Value::new_iutf8("ryomaechizen")),
        (Attribute::BadlistPassword, Value::new_iutf8("sampaguita")),
        (Attribute::BadlistPassword, Value::new_iutf8("sangreazul")),
        (Attribute::BadlistPassword, Value::new_iutf8("sarangheyo")),
        (Attribute::BadlistPassword, Value::new_iutf8("sassygirl1")),
        (Attribute::BadlistPassword, Value::new_iutf8("sasukeuchiha")),
        (Attribute::BadlistPassword, Value::new_iutf8("schokolade")),
        (Attribute::BadlistPassword, Value::new_iutf8("sebasteamo")),
        (Attribute::BadlistPassword, Value::new_iutf8("sectumsempra")),
        (Attribute::BadlistPassword, Value::new_iutf8("semeolvido")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("seniseviyorum")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("sentimiento")),
        (Attribute::BadlistPassword, Value::new_iutf8("sesshomaru")),
        (Attribute::BadlistPassword, Value::new_iutf8("sesshoumaru")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("sexandthecity")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("sexonthebeach")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("sexymomma1")),
        (Attribute::BadlistPassword, Value::new_iutf8("sexythang1")),
        (Attribute::BadlistPassword, Value::new_iutf8("sexything1")),
        (Attribute::BadlistPassword, Value::new_iutf8("shaggy2dope")),
        (Attribute::BadlistPassword, Value::new_iutf8("shippuuden")),
        (Attribute::BadlistPassword, Value::new_iutf8("shopaholic")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("showmethemoney")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("siemprejuntos")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("siempreteamare")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("simanjuntak")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("simplementeyo")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("sinterklaas")),
        (Attribute::BadlistPassword, Value::new_iutf8("sk8er4life")),
        (Attribute::BadlistPassword, Value::new_iutf8("skateordie")),
        (Attribute::BadlistPassword, Value::new_iutf8("soloparami")),
        (Attribute::BadlistPassword, Value::new_iutf8("soloparati")),
        (Attribute::BadlistPassword, Value::new_iutf8("somostuyyo")),
        (Attribute::BadlistPassword, Value::new_iutf8("souljaboy1")),
        (Attribute::BadlistPassword, Value::new_iutf8("souljagirl")),
        (Attribute::BadlistPassword, Value::new_iutf8("souljagurl")),
        (Attribute::BadlistPassword, Value::new_iutf8("soyelmejor")),
        (Attribute::BadlistPassword, Value::new_iutf8("soylamejor")),
        (Attribute::BadlistPassword, Value::new_iutf8("soylomaximo")),
        (Attribute::BadlistPassword, Value::new_iutf8("soylomejor")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("spongebobsquarepants")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("steauabucuresti")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("suankularb")),
        (Attribute::BadlistPassword, Value::new_iutf8("subhanallah")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("sugarandspice")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("sugarnspice")),
        (Attribute::BadlistPassword, Value::new_iutf8("superchica")),
        (Attribute::BadlistPassword, Value::new_iutf8("superinggo")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("superpoderosa")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("supladitah")),
        (Attribute::BadlistPassword, Value::new_iutf8("tamagotchi")),
        (Attribute::BadlistPassword, Value::new_iutf8("taugammaphi")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("teamareporsiempre")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("teamaresiempre")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("teamarex100pre")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("teamarexsiempre")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("teamobebito")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("teamodemasiado")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("teamogordo")),
        (Attribute::BadlistPassword, Value::new_iutf8("teamomiamor")),
        (Attribute::BadlistPassword, Value::new_iutf8("teamomibebe")),
        (Attribute::BadlistPassword, Value::new_iutf8("teamomivida")),
        (Attribute::BadlistPassword, Value::new_iutf8("teamosoloati")),
        (Attribute::BadlistPassword, Value::new_iutf8("teamotanto")),
        (Attribute::BadlistPassword, Value::new_iutf8("teamox100pre")),
        (Attribute::BadlistPassword, Value::new_iutf8("tecnologia")),
        (Attribute::BadlistPassword, Value::new_iutf8("teextraño")),
        (Attribute::BadlistPassword, Value::new_iutf8("teiubescmult")),
        (Attribute::BadlistPassword, Value::new_iutf8("tekelomucho")),
        (Attribute::BadlistPassword, Value::new_iutf8("tekelomuxo")),
        (Attribute::BadlistPassword, Value::new_iutf8("tekieromucho")),
        (Attribute::BadlistPassword, Value::new_iutf8("tekieromuxo")),
        (Attribute::BadlistPassword, Value::new_iutf8("telecomanda")),
        (Attribute::BadlistPassword, Value::new_iutf8("teletubbies")),
        (Attribute::BadlistPassword, Value::new_iutf8("tenecesito")),
        (Attribute::BadlistPassword, Value::new_iutf8("tengounamor")),
        (Attribute::BadlistPassword, Value::new_iutf8("teolvidare")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("tequieromucho")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("tequieromuxo")),
        (Attribute::BadlistPassword, Value::new_iutf8("tesigoamando")),
        (Attribute::BadlistPassword, Value::new_iutf8("thaitanium")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("theblackparade")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("theoneandonly")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("theveronicas")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("thisismypassword")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("threedaysgrace")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("timbiriche")),
        (Attribute::BadlistPassword, Value::new_iutf8("tinkywinky")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("titoelbambino")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("tivogliobene")),
        (Attribute::BadlistPassword, Value::new_iutf8("todalavida")),
        (Attribute::BadlistPassword, Value::new_iutf8("todocambio")),
        (Attribute::BadlistPassword, Value::new_iutf8("todopoderoso")),
        (Attribute::BadlistPassword, Value::new_iutf8("tohoshinki")),
        (Attribute::BadlistPassword, Value::new_iutf8("tokio hotel")),
        (Attribute::BadlistPassword, Value::new_iutf8("tomandjerry")),
        (Attribute::BadlistPassword, Value::new_iutf8("tomwelling")),
        (Attribute::BadlistPassword, Value::new_iutf8("trandafiri")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("trincheranorte")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("triskelion")),
        (Attribute::BadlistPassword, Value::new_iutf8("tueresmiamor")),
        (Attribute::BadlistPassword, Value::new_iutf8("tueresmivida")),
        (Attribute::BadlistPassword, Value::new_iutf8("tumamacalata")),
        (Attribute::BadlistPassword, Value::new_iutf8("tuttifrutti")),
        (Attribute::BadlistPassword, Value::new_iutf8("tuyyox100pre")),
        (Attribute::BadlistPassword, Value::new_iutf8("uchihasasuke")),
        (Attribute::BadlistPassword, Value::new_iutf8("undermyskin")),
        (Attribute::BadlistPassword, Value::new_iutf8("unforgetable")),
        (Attribute::BadlistPassword, Value::new_iutf8("unodostres")),
        (Attribute::BadlistPassword, Value::new_iutf8("vacaciones")),
        (Attribute::BadlistPassword, Value::new_iutf8("valderrama")),
        (Attribute::BadlistPassword, Value::new_iutf8("vatoslocos")),
        (Attribute::BadlistPassword, Value::new_iutf8("verjaardag")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("vetealamierda")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("veterinaria")),
        (Attribute::BadlistPassword, Value::new_iutf8("villacorta")),
        (Attribute::BadlistPassword, Value::new_iutf8("vivaelrock")),
        (Attribute::BadlistPassword, Value::new_iutf8("vivalaraza")),
        (Attribute::BadlistPassword, Value::new_iutf8("vivalavida")),
        (Attribute::BadlistPassword, Value::new_iutf8("vivelavida")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("webelongtogether")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("weezyfbaby")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("welcometomylife")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("whereisthelove")
        ),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("winniethepooh")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("wipemedown")),
        (Attribute::BadlistPassword, Value::new_iutf8("wisinyandel")),
        (Attribute::BadlistPassword, Value::new_iutf8("wisinyyandel")),
        (
            Attribute::BadlistPassword,
            Value::new_iutf8("worldofwarcraft")
        ),
        (Attribute::BadlistPassword, Value::new_iutf8("yosoyelmejor")),
        (Attribute::BadlistPassword, Value::new_iutf8("yosoylamejor")),
        (Attribute::BadlistPassword, Value::new_iutf8("youcantseeme")),
        (Attribute::BadlistPassword, Value::new_iutf8("yougotserved")),
        (Attribute::BadlistPassword, Value::new_iutf8("yuyuhakusho")),
        (Attribute::BadlistPassword, Value::new_iutf8("zonnebloem"))
    );
}
