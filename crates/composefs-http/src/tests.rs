use std::{sync::Mutex, time::Duration};

use composefs::{
    fsverity::Sha256HashValue, progress::test_support::RecordingReporter, test::TestRepo,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_DELAY: Duration = Duration::from_millis(40);
const MAX_HEADER_BYTES: usize = 8192;
const STREAM: usize = 0;
const OBJECT: usize = 1;

type Routes = HashMap<String, (Vec<u8>, usize)>;

#[derive(Default)]
struct Requests {
    counts: HashMap<String, usize>,
    active: [usize; 2],
    maximum: [usize; 2],
}

struct Server {
    url: Url,
    requests: Arc<Mutex<Requests>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<()>>>,
}

impl Server {
    async fn new(routes: Routes) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let requests = Arc::new(Mutex::new(Requests::default()));
        let stats = Arc::clone(&requests);
        let routes = Arc::new(routes);
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    connection = listener.accept() => {
                        let (socket, _) = connection?;
                        let routes = Arc::clone(&routes);
                        let stats = Arc::clone(&stats);
                        connections.spawn(async move {
                            timeout(TEST_TIMEOUT, serve(socket, routes, stats)).await?
                        });
                    }
                    Some(result) = connections.join_next() => { result??; }
                }
            }
            while let Some(result) = connections.join_next().await {
                result??;
            }
            Ok(())
        });
        Ok(Self {
            url,
            requests,
            stop: Some(stop),
            task: Some(task),
        })
    }

    async fn finish(mut self) -> Result<()> {
        self.stop.take().unwrap().send(()).expect("server running");
        timeout(TEST_TIMEOUT, self.task.as_mut().unwrap()).await???;
        self.task.take();
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve(
    socket: TcpStream,
    routes: Arc<Routes>,
    requests: Arc<Mutex<Requests>>,
) -> Result<()> {
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let path = line
        .split_whitespace()
        .nth(1)
        .context("HTTP path")?
        .to_owned();
    let mut header_bytes = line.len();
    loop {
        line.clear();
        anyhow::ensure!(
            reader.read_line(&mut line).await? > 0,
            "HTTP headers truncated"
        );
        header_bytes += line.len();
        anyhow::ensure!(header_bytes < MAX_HEADER_BYTES, "HTTP headers too large");
        if line == "\r\n" {
            break;
        }
    }
    let (body, class, status) = match routes.get(&path) {
        Some((body, class)) => (body.as_slice(), *class, "200 OK"),
        None => (&b"missing"[..], OBJECT, "404 Not Found"),
    };
    {
        let mut stats = requests.lock().unwrap();
        *stats.counts.entry(path).or_default() += 1;
        stats.active[class] += 1;
        stats.maximum[class] = stats.maximum[class].max(stats.active[class]);
    }
    // Hold requests open so overlap is observed without measuring elapsed time.
    sleep(RESPONSE_DELAY).await;
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut socket = reader.into_inner();
    socket.write_all(response.as_bytes()).await?;
    socket.write_all(body).await?;
    requests.lock().unwrap().active[class] -= 1;
    Ok(())
}

fn object_path(id: &Sha256HashValue) -> String {
    format!("/objects/{}", id.to_object_pathname())
}

fn add_route(
    routes: &mut Routes,
    repo: &Repository<Sha256HashValue>,
    id: &Sha256HashValue,
    class: usize,
) -> Result<()> {
    routes.insert(object_path(id), (repo.read_object(id)?, class));
    Ok(())
}

fn checksum(data: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(data);
    format!("sha256:{}", hex::encode(hash.finalize()))
}

async fn fetch(
    server: &Server,
    repo: Arc<Repository<Sha256HashValue>>,
    reporter: SharedReporter,
) -> Result<(String, Sha256HashValue)> {
    let downloader = Arc::new(Downloader {
        client: Client::builder().no_proxy().build()?,
        repo,
        url: server.url.clone(),
        reporter,
    });
    timeout(TEST_TIMEOUT, downloader.ensure_stream("root")).await?
}

#[tokio::test]
async fn bounded_fetches_and_deduplication() -> Result<()> {
    let source = TestRepo::<Sha256HashValue>::new();
    let destination = TestRepo::<Sha256HashValue>::new();
    let mut routes = Routes::new();
    let count = MAX_CONCURRENT_REQUESTS * 3 + 1;
    let mut children = Vec::new();
    let mut objects = Vec::new();
    let shared = b"shared object";
    let shared_id = source.repo.ensure_object(shared)?;
    add_route(&mut routes, &source.repo, &shared_id, OBJECT)?;
    for i in 0..count {
        let data = format!("object {i}").into_bytes();
        let id = source.repo.ensure_object(&data)?;
        add_route(&mut routes, &source.repo, &id, OBJECT)?;
        objects.push(id);
        let mut writer = source.repo.create_stream(0)?;
        writer.write_external(&data)?;
        writer.write_external(shared)?;
        writer.write_external(shared)?;
        let mut body = data;
        body.extend_from_slice(shared);
        body.extend_from_slice(shared);
        let child = writer.done()?;
        add_route(&mut routes, &source.repo, &child, STREAM)?;
        children.push((child, checksum(&body)));
    }
    // The root sees this as an ordinary object before the intermediate stream
    // discovers that it is a splitstream. It must not be queued again later.
    let late_id = children[0].0.clone();
    let mut intermediate = source.repo.create_stream(0)?;
    for (id, body) in &children {
        intermediate.add_named_stream_ref(body, id);
    }
    let intermediate_id = intermediate.done()?;
    add_route(&mut routes, &source.repo, &intermediate_id, STREAM)?;
    let mut root = source.repo.create_stream(0)?;
    root.write_reference(late_id.clone())?;
    root.add_named_stream_ref(&checksum(b""), &intermediate_id);
    root.add_named_stream_ref(&children[1].1, &children[1].0);
    let root_id = root.done()?;
    let root_bytes = source.repo.read_object(&root_id)?;
    routes.insert("/streams/root".into(), (root_bytes, STREAM));
    let expected_paths: HashSet<_> = routes.keys().cloned().collect();
    let server = Server::new(routes).await?;
    let reporter = Arc::new(RecordingReporter::new());
    let (body, id) = fetch(&server, Arc::clone(&destination.repo), reporter.clone()).await?;
    assert_eq!(id, root_id);
    assert_eq!(body, checksum(&source.repo.read_object(&late_id)?));
    for id in objects
        .iter()
        .chain(std::iter::once(&shared_id))
        .chain(children.iter().map(|(id, _)| id))
        .chain([&root_id, &intermediate_id])
    {
        assert_eq!(
            destination.repo.read_object(id)?,
            source.repo.read_object(id)?
        );
    }
    {
        let stats = server.requests.lock().unwrap();
        assert_eq!(
            stats.counts.keys().cloned().collect::<HashSet<_>>(),
            expected_paths
        );
        assert!(stats.counts.values().all(|count| *count == 1));
        for maximum in stats.maximum {
            assert!(maximum > 1, "fetches did not overlap");
            assert!(
                maximum <= MAX_CONCURRENT_REQUESTS,
                "fetch limit exceeded: {maximum}"
            );
        }
    }
    assert!(reporter.events().iter().any(|event| matches!(event,
        ProgressEvent::Started { total: Some(total), .. } if *total == (count + 1) as u64
    )));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn fetch_failures_identify_object() -> Result<()> {
    for splitstream in [false, true] {
        for corrupt in [false, true] {
            let source = TestRepo::<Sha256HashValue>::new();
            let destination = TestRepo::<Sha256HashValue>::new();
            let mut child = source.repo.create_stream(0)?;
            child.write_inline(b"child");
            let id = if splitstream {
                child.done()?
            } else {
                source.repo.ensure_object(b"object")?
            };
            let mut root = source.repo.create_stream(0)?;
            if splitstream {
                root.add_named_stream_ref(&checksum(b"child"), &id);
            } else {
                root.write_reference(id.clone())?;
            }
            let root_id = root.done()?;
            let mut routes = Routes::from([(
                "/streams/root".into(),
                (source.repo.read_object(&root_id)?, STREAM),
            )]);
            if corrupt {
                routes.insert(
                    object_path(&id),
                    (
                        b"wrong content".to_vec(),
                        if splitstream { STREAM } else { OBJECT },
                    ),
                );
            }
            let server = Server::new(routes).await?;
            let error = fetch(
                &server,
                Arc::clone(&destination.repo),
                Arc::new(NullReporter),
            )
            .await
            .unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(&format!("{id:?}")), "{message}");
            assert!(
                message.contains(if corrupt { "fs-verity" } else { "404" }),
                "{message}"
            );
            server.finish().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn verifies_splitstream_body_checksum() -> Result<()> {
    for conflicting in [false, true] {
        let source = TestRepo::<Sha256HashValue>::new();
        let destination = TestRepo::<Sha256HashValue>::new();
        let mut child = source.repo.create_stream(0)?;
        child.write_inline(b"child");
        let child_id = child.done()?;
        let mut root = source.repo.create_stream(0)?;
        root.add_named_stream_ref(&checksum(b"wrong"), &child_id);
        if conflicting {
            root.add_named_stream_ref(&checksum(b"child"), &child_id);
        }
        let root_id = root.done()?;
        let mut routes = Routes::from([(
            "/streams/root".into(),
            (source.repo.read_object(&root_id)?, STREAM),
        )]);
        add_route(&mut routes, &source.repo, &child_id, STREAM)?;
        let server = Server::new(routes).await?;
        let error = fetch(
            &server,
            Arc::clone(&destination.repo),
            Arc::new(NullReporter),
        )
        .await
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(&format!("{child_id:?}")), "{message}");
        assert!(
            message.contains(if conflicting {
                "different body hashes"
            } else {
                "should have checksum"
            }),
            "{message}"
        );
        server.finish().await?;
    }
    Ok(())
}
