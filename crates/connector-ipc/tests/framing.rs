use connector_ipc::{ConnectorCall, Envelope, read_envelope, write_envelope};
use tokio::io::duplex;

#[tokio::test]
async fn envelope_round_trips_over_length_delimited_stream() {
    let (mut writer, mut reader) = duplex(16 * 1024);
    let envelope = Envelope::request("request-1", &ConnectorCall::GetPackManifest).unwrap();
    let write = tokio::spawn(async move { write_envelope(&mut writer, &envelope).await });
    let decoded = read_envelope(&mut reader).await.unwrap().unwrap();
    write.await.unwrap().unwrap();
    assert_eq!(decoded.request_id, "request-1");
    assert!(matches!(
        decoded.decode_payload::<ConnectorCall>().unwrap(),
        ConnectorCall::GetPackManifest
    ));
}

#[test]
fn worker_paths_must_be_absolute() {
    let Err(error) = connector_ipc::WorkerClient::spawn("relative-worker", "sql") else {
        panic!("relative worker path should be rejected");
    };
    assert!(error.to_string().contains("absolute"));
}
