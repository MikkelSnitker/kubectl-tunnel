use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction as LayoutDirection, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
#[derive(Clone, Copy)]
pub enum PacketDirection {
    Outbound,
    Inbound,
}

#[derive(Clone, Copy)]
pub enum TunnelConnectionStatus {
    Initializing,
    Connecting,
    Connected,
    Reconnecting,
    Disconnected,
    Error,
    Stopped,
}

impl TunnelConnectionStatus {
    pub fn label(self) -> &'static str {
        match self {
            TunnelConnectionStatus::Initializing => "Initializing",
            TunnelConnectionStatus::Connecting => "Connecting",
            TunnelConnectionStatus::Connected => "Connected",
            TunnelConnectionStatus::Reconnecting => "Reconnecting",
            TunnelConnectionStatus::Disconnected => "Disconnected",
            TunnelConnectionStatus::Error => "Error",
            TunnelConnectionStatus::Stopped => "Stopped",
        }
    }
}

#[derive(Clone)]
pub struct TopBarState {
    pub status: TunnelConnectionStatus,
    pub address: Option<String>,
    pub destination: Option<String>,
}

impl TopBarState {
    pub fn new(status: TunnelConnectionStatus) -> Self {
        Self {
            status,
            address: None,
            destination: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Proto {
    Tcp,
    Udp,
    Other(u8),
}

impl Proto {
    fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
            Proto::Other(_) => "IP",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpState {
    Unknown,
    SynSent,
    SynRecv,
    Established,
    FinWait,
    Closed,
    Reset,
}

impl TcpState {
    fn label(self) -> &'static str {
        match self {
            TcpState::Unknown => "-",
            TcpState::SynSent => "SYN-SENT",
            TcpState::SynRecv => "SYN-RECV",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait => "FIN-WAIT",
            TcpState::Closed => "CLOSED",
            TcpState::Reset => "RESET",
        }
    }
}

#[derive(Clone, Copy)]
struct TcpFlags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SessionKey {
    proto: Proto,
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
}

struct SessionStats {
    first_seen: Instant,
    last_seen: Instant,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
    prev_tx_bytes: u64,
    prev_rx_bytes: u64,
    prev_rate_at: Instant,
    tx_bps: f64,
    rx_bps: f64,
    tcp_state: TcpState,
}

pub struct SessionRow {
    pub proto: &'static str,
    pub state: &'static str,
    pub local: String,
    pub remote: String,
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub age: Duration,
    pub idle: Duration,
}

pub struct Snapshot {
    pub rows: Vec<SessionRow>,
    pub active_sessions: usize,
    pub total_tx_bps: u64,
    pub total_rx_bps: u64,
}

pub struct SessionTracker {
    sessions: HashMap<SessionKey, SessionStats>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn observe(&mut self, direction: PacketDirection, packet: &[u8]) {
        let Some(parsed) = ParsedPacket::parse(packet) else {
            return;
        };

        let (local, local_port, remote, remote_port, tx, rx) = match direction {
            PacketDirection::Outbound => (
                parsed.src,
                parsed.src_port,
                parsed.dst,
                parsed.dst_port,
                packet.len() as u64,
                0,
            ),
            PacketDirection::Inbound => (
                parsed.dst,
                parsed.dst_port,
                parsed.src,
                parsed.src_port,
                0,
                packet.len() as u64,
            ),
        };

        let key = SessionKey {
            proto: parsed.proto,
            local,
            local_port,
            remote,
            remote_port,
        };

        let now = Instant::now();
        let entry = self.sessions.entry(key).or_insert_with(|| SessionStats {
            first_seen: now,
            last_seen: now,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_packets: 0,
            rx_packets: 0,
            prev_tx_bytes: 0,
            prev_rx_bytes: 0,
            prev_rate_at: now,
            tx_bps: 0.0,
            rx_bps: 0.0,
            tcp_state: TcpState::Unknown,
        });

        entry.last_seen = now;
        entry.tx_bytes += tx;
        entry.rx_bytes += rx;
        if tx > 0 {
            entry.tx_packets += 1;
        }
        if rx > 0 {
            entry.rx_packets += 1;
        }

        if parsed.proto == Proto::Tcp
            && let Some(flags) = parsed.tcp_flags
        {
            entry.tcp_state = next_tcp_state(entry.tcp_state, flags);
        }
    }

    pub fn snapshot(&mut self) -> Snapshot {
        let now = Instant::now();
        let mut rows = Vec::with_capacity(self.sessions.len());
        let mut total_tx_bps = 0_u64;
        let mut total_rx_bps = 0_u64;

        self.sessions
            .retain(|_, stats| now.duration_since(stats.last_seen) < Duration::from_secs(120));

        for (key, stats) in &mut self.sessions {
            let elapsed = now.duration_since(stats.prev_rate_at).as_secs_f64();
            if elapsed >= 0.25 {
                let dtx = stats.tx_bytes.saturating_sub(stats.prev_tx_bytes);
                let drx = stats.rx_bytes.saturating_sub(stats.prev_rx_bytes);
                stats.tx_bps = dtx as f64 / elapsed;
                stats.rx_bps = drx as f64 / elapsed;
                stats.prev_tx_bytes = stats.tx_bytes;
                stats.prev_rx_bytes = stats.rx_bytes;
                stats.prev_rate_at = now;
            }

            let tx_bps = stats.tx_bps.round().max(0.0) as u64;
            let rx_bps = stats.rx_bps.round().max(0.0) as u64;
            total_tx_bps += tx_bps;
            total_rx_bps += rx_bps;

            rows.push(SessionRow {
                proto: key.proto.label(),
                state: stats.tcp_state.label(),
                local: format!("{}:{}", key.local, key.local_port),
                remote: format!("{}:{}", key.remote, key.remote_port),
                tx_bps,
                rx_bps,
                tx_bytes: stats.tx_bytes,
                rx_bytes: stats.rx_bytes,
                age: now.duration_since(stats.first_seen),
                idle: now.duration_since(stats.last_seen),
            });
        }

        rows.sort_by_key(|r| std::cmp::Reverse(r.tx_bps + r.rx_bps));

        Snapshot {
            active_sessions: rows.len(),
            rows,
            total_tx_bps,
            total_rx_bps,
        }
    }
}

struct ParsedPacket {
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    proto: Proto,
    tcp_flags: Option<TcpFlags>,
}

impl ParsedPacket {
    fn parse(data: &[u8]) -> Option<Self> {
        let version = data.first().copied()? >> 4;
        match version {
            4 => Self::parse_v4(data),
            6 => Self::parse_v6(data),
            _ => None,
        }
    }

    fn parse_v4(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if ihl < 20 || data.len() < ihl + 4 {
            return None;
        }

        let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
        let proto = match data[9] {
            6 => Proto::Tcp,
            17 => Proto::Udp,
            p => Proto::Other(p),
        };

        let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
        let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
        let tcp_flags = parse_tcp_flags(data, ihl, proto)?;

        Some(Self {
            src,
            dst,
            src_port,
            dst_port,
            proto,
            tcp_flags,
        })
    }

    fn parse_v6(data: &[u8]) -> Option<Self> {
        if data.len() < 44 {
            return None;
        }

        let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?));
        let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?));
        let proto = match data[6] {
            6 => Proto::Tcp,
            17 => Proto::Udp,
            p => Proto::Other(p),
        };

        let src_port = u16::from_be_bytes([data[40], data[41]]);
        let dst_port = u16::from_be_bytes([data[42], data[43]]);
        let tcp_flags = parse_tcp_flags(data, 40, proto)?;

        Some(Self {
            src,
            dst,
            src_port,
            dst_port,
            proto,
            tcp_flags,
        })
    }
}

fn parse_tcp_flags(data: &[u8], transport_offset: usize, proto: Proto) -> Option<Option<TcpFlags>> {
    if proto != Proto::Tcp {
        return Some(None);
    }
    if data.len() < transport_offset + 14 {
        return None;
    }
    let flags = data[transport_offset + 13];
    Some(Some(TcpFlags {
        fin: flags & 0x01 != 0,
        syn: flags & 0x02 != 0,
        rst: flags & 0x04 != 0,
        ack: flags & 0x10 != 0,
    }))
}

fn next_tcp_state(current: TcpState, flags: TcpFlags) -> TcpState {
    if flags.rst {
        return TcpState::Reset;
    }
    if flags.syn && flags.ack {
        return TcpState::SynRecv;
    }
    if flags.syn {
        return TcpState::SynSent;
    }
    if flags.fin {
        return TcpState::FinWait;
    }
    if flags.ack {
        return match current {
            TcpState::SynSent | TcpState::SynRecv | TcpState::Unknown => TcpState::Established,
            TcpState::FinWait => TcpState::Closed,
            TcpState::Reset => TcpState::Reset,
            state => state,
        };
    }
    current
}

pub fn run_ui(
    tracker: Arc<Mutex<SessionTracker>>,
    stop: Arc<AtomicBool>,
    tun_name: String,
    pod_name: String,
    top_bar: Arc<RwLock<TopBarState>>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    while !stop.load(Ordering::Relaxed) {
        let top = top_bar
            .read()
            .map(|t| t.clone())
            .unwrap_or_else(|_| TopBarState::new(TunnelConnectionStatus::Error));

        let snapshot = {
            let mut guard = tracker
                .lock()
                .map_err(|_| io::Error::other("session tracker lock poisoned"))?;
            guard.snapshot()
        };

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(LayoutDirection::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(1),
                ])
                .split(f.area());

            let header = Paragraph::new(format!(
                "TUN: {}  Pod: {}  Status: {}  Addr: {}  Dst: {}  Active: {}  TX: {}/s  RX: {}/s",
                tun_name,
                pod_name,
                top.status.label(),
                top.address.as_deref().unwrap_or("-"),
                top.destination.as_deref().unwrap_or("-"),
                snapshot.active_sessions,
                format_bytes(snapshot.total_tx_bps),
                format_bytes(snapshot.total_rx_bps)
            ))
            .block(Block::default().borders(Borders::ALL).title("Tunnel"));
            f.render_widget(header, chunks[0]);

            let rows: Vec<Row> = snapshot
                .rows
                .iter()
                .take(200)
                .map(|s| {
                    Row::new(vec![
                        Cell::from(s.proto.to_string()),
                        Cell::from(s.state.to_string()),
                        Cell::from(s.local.clone()),
                        Cell::from(s.remote.clone()),
                        Cell::from(format_bytes(s.tx_bps)),
                        Cell::from(format_bytes(s.rx_bps)),
                        Cell::from(format_bytes(s.tx_bytes)),
                        Cell::from(format_bytes(s.rx_bytes)),
                        Cell::from(format_duration(s.age)),
                        Cell::from(format_duration(s.idle)),
                    ])
                })
                .collect();

            let widths = [
                Constraint::Length(5),
                Constraint::Length(12),
                Constraint::Length(27),
                Constraint::Length(27),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(8),
                Constraint::Length(8),
            ];

            let table = Table::new(rows, widths)
                .header(
                    Row::new(vec![
                        "Proto", "State", "Local", "Remote", "TX/s", "RX/s", "TX", "RX", "Age",
                        "Idle",
                    ])
                    .style(Style::default().fg(Color::Cyan)),
                )
                .block(Block::default().borders(Borders::ALL).title("Sessions"));
            f.render_widget(table, chunks[1]);

            let footer = Paragraph::new("q: quit  esc: quit");
            f.render_widget(footer, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(150))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
        {
            stop.store(true, Ordering::Relaxed);
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes}{}", UNITS[unit])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m");
    }
    let hours = mins / 60;
    format!("{hours}h")
}
