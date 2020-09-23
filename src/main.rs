mod header;
mod message;
mod query;
mod rdns;
mod resource_record;
mod shared;
use futures_util::stream::StreamExt;
use mdns::{Record, RecordKind};
use std::{net::IpAddr, time::Duration};

//const SERVICE_NAME: &'static str = "_googlecast._tcp.local";

#[tokio::main]
async fn main() {
    //discover_specific_service().await;
    //discover_all_services().await;
    //rdns::mdns();
    rdns::net_mdns();
}

fn to_ip_addr(record: &Record) -> Option<IpAddr> {
    match record.kind.clone() {
        RecordKind::A(addr) => Some(addr.into()),
        RecordKind::AAAA(addr) => Some(addr.into()),
        _ => None,
    }
}
async fn discover_specific_service() {
    //let service_name = "_arduino._udp.local";
    //let service_name = "_hap._tcp.local";
    let service_name = "_fabrlyn._udp.local";
    let record_stream = mdns::discover::all(service_name, Duration::from_secs(15))
        .unwrap()
        .listen();

    let mut record_stream = Box::pin(record_stream);
    while let Some(Ok(response)) = record_stream.next().await {
        println!("Response: {:?}", response);
        let addr = response.records().filter_map(to_ip_addr).next();

        response
            .records()
            .for_each(|r| println!("name: {:?}", r.name));

        if let Some(addr) = addr {
            println!("found cast device at {}", addr);
        } else {
            println!("cast device does not advertise address");
        }
    }
}

async fn discover_all_services() {
    println!("Discovering all services");

    let service_name = "_services._dns-sd._udp.local";

    let record_stream = mdns::discover::all(service_name, Duration::from_secs(15))
        .unwrap()
        .listen();
    let mut record_stream = Box::pin(record_stream);

    while let Some(Ok(response)) = record_stream.next().await {
        println!("Response: {:?}", response);
        let addr = response.records().filter_map(to_ip_addr).next();

        if let Some(addr) = addr {
            println!("found cast device at {}", addr);
        } else {
            println!("cast device does not advertise address");
        }
    }
}
