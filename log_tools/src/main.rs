use anyhow::{Result, anyhow};
use clap::{Arg, Command as ClapCommand};
use plotters::prelude::*;
use plotters::style::RGBColor;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use once_cell::sync::Lazy; // Add dependency: once_cell

macro_rules! warn {
    ($msg:expr) => {
        println!("WARNING: {}", $msg);
    };
}

#[derive(Clone, Serialize, Deserialize)]
struct LogAnalyzerConfig {
    package_name: String,
    keyword_regex: String,
    output_file: Option<String>,
    sample_interval: u64,
}

#[derive(Clone)]
struct LogAnalyzer {
    config: LogAnalyzerConfig,
    adb_path: String,
}

#[derive(Serialize)]
struct MemorySample {
    timestamp: u64,
    total_pss: u64,
    native_heap: u64,
    dalvik_heap: u64,
    code: u64,
    stack: u64,
    graphics: u64,
    private_dirty: u64,
    shared_dirty: u64,
}

#[derive(Serialize)]
struct SoMemoryInfo {
    name: String,
    pss: u64,
    private_dirty: u64,
    shared_dirty: u64,
}

#[derive(Serialize)]
struct ThreadInfo {
    tid: String,
    name: String,
    state: String,
    priority: String,
    user_time: String,
    system_time: String,
}

#[cfg(windows)]
fn setup_utf8() {
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("cmd")
        .arg("/C")
        .arg("chcp")
        .arg("65001")
        .creation_flags(0x08000000)
        .status();
}

// Precompiled regexes
static SO_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+\.so)").unwrap());
static MEM_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(.+):\s+(\d+)").unwrap());

impl LogAnalyzer {
    fn new(config: LogAnalyzerConfig) -> Self {
        LogAnalyzer {
            config,
            adb_path: "adb".to_string(),
        }
    }

    fn start_logcat(&self) -> Result<()> {
        let re = Regex::new(&self.config.keyword_regex)?;
        let mut output = Command::new(&self.adb_path)
            .args(&["logcat", "-v", "time"])
            .stdout(Stdio::piped())
            .spawn()?;
        let stdout = output.stdout.take().ok_or(anyhow!("Failed to get stdout"))?;
        let mut reader = BufReader::new(stdout);
        let mut buffer = Vec::new();

        if let Some(ref file_path) = self.config.output_file {
            let file = File::create(file_path)?;
            let mut file = BufWriter::new(file);
            while reader.read_until(b'\n', &mut buffer)? > 0 {
                let line = String::from_utf8_lossy(&buffer);
                if re.is_match(&line) {
                    println!("Match found: {}", line);
                    file.write_all(&buffer)?;
                }
                buffer.clear();
            }
            file.flush()?;
        } else {
            while reader.read_until(b'\n', &mut buffer)? > 0 {
                let line = String::from_utf8_lossy(&buffer);
                if re.is_match(&line) {
                    println!("Match found: {}", line);
                }
                buffer.clear();
            }
        }
        output.kill()?;
        output.wait()?;
        Ok(())
    }

    fn monitor_memory(&self, duration: u64, output_image: &str) -> Result<Vec<MemorySample>> {
        let start = Instant::now();
        let mut samples = Vec::with_capacity((duration / self.config.sample_interval) as usize);
        let mut buffer = String::new();

        while start.elapsed().as_secs() < duration {
            buffer.clear();
            self.get_memory_info_into(&mut buffer)?;
            let sample = MemorySample {
                timestamp: start.elapsed().as_secs(),
                total_pss: parse_memory_value(&buffer, "TOTAL PSS:")?,
                native_heap: parse_memory_value(&buffer, "Native Heap:")?,
                dalvik_heap: parse_memory_value(&buffer, "Dalvik Heap:")?,
                code: parse_memory_value(&buffer, "Code:")?,
                stack: parse_memory_value(&buffer, "Stack:")?,
                graphics: parse_memory_value(&buffer, "Graphics:")?,
                private_dirty: parse_memory_value(&buffer, "Private Dirty:")?,
                shared_dirty: parse_memory_value(&buffer, "Shared Dirty:")?,
            };
            samples.push(sample);
            std::thread::sleep(Duration::from_secs(self.config.sample_interval));
        }

        self.plot_memory_curve(&samples, output_image)?;

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let json_file = format!("memory_samples_{}.json", &timestamp);
        let csv_file_path = format!("memory_samples_{}.csv", &timestamp);

        let json = serde_json::to_string_pretty(&samples)?;
        std::fs::write(&json_file, json)?;
        println!("Memory samples written to {}", json_file);

        let csv_file = File::create(&csv_file_path)?;
        let mut csv_file = BufWriter::new(csv_file);
        writeln!(
            csv_file,
            "timestamp,total_pss,native_heap,dalvik_heap,code,stack,graphics,private_dirty,shared_dirty"
        )?;
        for sample in &samples {
            writeln!(
                csv_file,
                "{},{},{},{},{},{},{},{},{}",
                sample.timestamp,
                sample.total_pss,
                sample.native_heap,
                sample.dalvik_heap,
                sample.code,
                sample.stack,
                sample.graphics,
                sample.private_dirty,
                sample.shared_dirty
            )?;
        }
        csv_file.flush()?;
        println!("Memory samples written to {}", csv_file_path);

        Ok(samples)
    }

    fn plot_memory_curve(&self, samples: &[MemorySample], output: &str) -> Result<()> {
        let root = BitMapBackend::new(output, (1200, 800)).into_drawing_area();
        root.fill(&WHITE)?;

        let max_pss = samples.iter().map(|s| s.total_pss as f64).max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap_or(1000.0) * 1.2;
        let max_time = samples.last().map(|s| s.timestamp as f64).unwrap_or(1.0);

        let mut chart = ChartBuilder::on(&root)
            .caption("Detailed Memory Usage Over Time", ("sans-serif", 40).into_font())
            .margin(10)
            .x_label_area_size(30)
            .y_label_area_size(50)
            .build_cartesian_2d(0f64..max_time, 0f64..max_pss)?;

        chart.configure_mesh().x_desc("Time (s)").y_desc("Memory (KB)").draw()?;

        let colors = [RED, BLUE, GREEN, CYAN, MAGENTA, YELLOW, BLACK, RGBColor(128, 0, 128)];
        let labels = ["Total PSS", "Native Heap", "Dalvik Heap", "Code", "Stack", "Graphics", "Private Dirty", "Shared Dirty"];
        let data_fns: &[fn(&MemorySample) -> (f64, f64)] = &[
            |s| (s.timestamp as f64, s.total_pss as f64),
            |s| (s.timestamp as f64, s.native_heap as f64),
            |s| (s.timestamp as f64, s.dalvik_heap as f64),
            |s| (s.timestamp as f64, s.code as f64),
            |s| (s.timestamp as f64, s.stack as f64),
            |s| (s.timestamp as f64, s.graphics as f64),
            |s| (s.timestamp as f64, s.private_dirty as f64),
            |s| (s.timestamp as f64, s.shared_dirty as f64),
        ];

        for (i, (color, label)) in colors.iter().zip(labels.iter()).enumerate() {
            let data: Vec<_> = samples.iter().map(data_fns[i]).collect();
            let color_clone = *color;
            chart.draw_series(LineSeries::new(data, color_clone))?
                .label(*label)
                .legend(move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color_clone));
        }

        chart.configure_series_labels()
            .background_style(&WHITE.mix(0.8))
            .border_style(&BLACK)
            .position(SeriesLabelPosition::UpperRight)
            .draw()?;

        root.present()?;
        println!("Memory usage plot saved to {}", output);
        Ok(())
    }

    fn analyze_threads(&self) -> Result<Vec<ThreadInfo>> {
        let pid = self.get_pid()?;
        let output = Command::new(&self.adb_path)
            .args(&["shell", "ps", "-T", "-p", &pid])
            .output()?;
        let ps_output = String::from_utf8_lossy(&output.stdout);

        let mut threads = Vec::new();
        for line in ps_output.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 9 {
                threads.push(ThreadInfo {
                    tid: fields[1].to_string(),
                    name: fields[8..].join(" "),
                    state: fields[4].to_string(),
                    priority: fields[5].to_string(),
                    user_time: fields[6].to_string(),
                    system_time: fields[7].to_string(),
                });
            }
        }

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let json_file = format!("thread_info_{}.json", &timestamp);
        let csv_file_path = format!("thread_info_{}.csv", &timestamp);

        let json = serde_json::to_string_pretty(&threads)?;
        std::fs::write(&json_file, json)?;
        println!("Thread info written to {}", json_file);

        let csv_file = File::create(&csv_file_path)?;
        let mut csv_file = BufWriter::new(csv_file);
        writeln!(csv_file, "tid,name,state,priority,user_time,system_time")?;
        for thread in &threads {
            writeln!(
                csv_file,
                "{},{},{},{},{},{}",
                thread.tid, thread.name, thread.state, thread.priority, thread.user_time, thread.system_time
            )?;
        }
        csv_file.flush()?;
        println!("Thread info written to {}", csv_file_path);

        Ok(threads)
    }

    fn analyze_so_memory(&self) -> Result<Vec<SoMemoryInfo>> {
        let mut buffer = String::new();
        self.get_memory_info_into(&mut buffer)?;
        let mut so_libs = Vec::new();
        let lines = buffer.lines().collect::<Vec<_>>();
        let mut in_so_section = false;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("Native Heap") {
                in_so_section = true;
                continue;
            }
            if in_so_section && (line.contains("Dalvik Heap") || line.trim().is_empty()) {
                break;
            }
            if i > 1000 { // Safety limit
                warn!("Reached line limit in .so parsing, stopping");
                break;
            }
            if in_so_section && !line.trim().is_empty() {
                if let Some(caps) = SO_REGEX.captures(line) {
                    let pss = caps.get(1).and_then(|m| m.as_str().parse::<u64>().ok()).unwrap_or(0);
                    let private_dirty = caps.get(2).and_then(|m| m.as_str().parse::<u64>().ok()).unwrap_or(0);
                    let shared_dirty = caps.get(3).and_then(|m| m.as_str().parse::<u64>().ok()).unwrap_or(0);
                    let name = caps.get(4).map_or("unknown.so", |m| m.as_str()).to_string();
                    so_libs.push(SoMemoryInfo { name, pss, private_dirty, shared_dirty });
                } else {
                    warn!(format!("Failed to parse .so line: {}", line));
                }
            }
        }

        if so_libs.is_empty() {
            warn!(format!("No .so libraries found in memory info for {}", self.config.package_name));
        } else {
            so_libs.sort_unstable_by(|a, b| b.pss.cmp(&a.pss));
        }

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let json_file = format!("so_memory_{}.json", &timestamp);
        let csv_file_path = format!("so_memory_{}.csv", &timestamp);

        let json = serde_json::to_string_pretty(&so_libs)?;
        std::fs::write(&json_file, json)?;
        println!("SO memory info written to {}", json_file);

        let csv_file = File::create(&csv_file_path)?;
        let mut csv_file = BufWriter::new(csv_file);
        writeln!(csv_file, "name,pss,private_dirty,shared_dirty")?;
        for so in &so_libs {
            writeln!(csv_file, "{},{},{},{}", so.name, so.pss, so.private_dirty, so.shared_dirty)?;
        }
        csv_file.flush()?;
        println!("SO memory info written to {}", csv_file_path);

        Ok(so_libs)
    }

    fn get_memory_info_into(&self, buffer: &mut String) -> Result<()> {
        let output = Command::new(&self.adb_path)
            .args(&["shell", "dumpsys", "meminfo", &self.config.package_name])
            .output()?;
        buffer.clear();
        buffer.push_str(&String::from_utf8_lossy(&output.stdout));
        Ok(())
    }

    fn get_pid(&self) -> Result<String> {
        let output = Command::new(&self.adb_path)
            .args(&["shell", "pidof", &self.config.package_name])
            .output()?;
        let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if pid.is_empty() {
            Err(anyhow!("Process {} not found on device", self.config.package_name))
        } else {
            Ok(pid)
        }
    }
}

fn parse_memory_value(mem_info: &str, key: &str) -> Result<u64> {
    for line in mem_info.lines() {
        if let Some(caps) = MEM_REGEX.captures(line) {
            if caps.get(1).map_or(false, |m| m.as_str().trim() == key) {
                return caps.get(2)
                    .and_then(|m| m.as_str().parse::<u64>().ok())
                    .ok_or_else(|| anyhow!("Failed to parse {} value", key));
            }
        }
    }
    warn!(format!("Could not find {} in meminfo", key));
    Ok(0)
}

fn main() -> Result<()> {
    setup_utf8();
    let adb_check = Command::new("adb").arg("version").output();
    if adb_check.is_err() {
        return Err(anyhow!("ADB is not installed or not found in PATH"));
    }

    let matches = ClapCommand::new("Android Log Analyzer")
        .version("1.0")
        .about("Analyzes Android logs, memory, and threads via ADB")
        .arg(Arg::new("config").short('c').long("config").value_name("CONFIG").help("Path to JSON config file"))
        .arg(Arg::new("package").short('p').long("package").value_name("PACKAGE").help("Target package name"))
        .arg(Arg::new("regex").short('r').long("regex").value_name("REGEX").help("Keyword regex for log filtering"))
        .arg(Arg::new("memory").short('m').long("memory").value_name("DURATION").help("Monitor and plot memory usage for specified duration (seconds)").default_missing_value("60"))
        .arg(Arg::new("threads").short('t').long("threads").help("Analyze process threads").action(clap::ArgAction::SetTrue))
        .arg(Arg::new("so_memory").short('s').long("so-memory").help("Analyze .so library memory usage").action(clap::ArgAction::SetTrue))
        .get_matches();

    let mut config = if let Some(config_path) = matches.get_one::<String>("config") {
        let file = File::open(config_path)?;
        serde_json::from_reader(file)?
    } else {
        LogAnalyzerConfig {
            package_name: "com.example.app".to_string(),
            keyword_regex: "ERROR|WARNING".to_string(),
            output_file: Some("filtered_logs.txt".to_string()),
            sample_interval: 1,
        }
    };

    if let Some(package) = matches.get_one::<String>("package") {
        config.package_name = package.clone();
    }
    if let Some(regex) = matches.get_one::<String>("regex") {
        config.keyword_regex = regex.clone();
    }

    let analyzer = LogAnalyzer::new(config);
    let mut executed = false;

    if matches.get_flag("threads") {
        let threads = analyzer.analyze_threads()?;
        println!("Thread Analysis:");
        for thread in &threads {
            println!("TID: {:<6} Name: {:<20} State: {:<2} Priority: {:<3} User Time: {:<6} System Time: {}",
                thread.tid, thread.name, thread.state, thread.priority, thread.user_time, thread.system_time);
        }
        executed = true;
    }

    if matches.contains_id("memory") {
        let duration = matches.get_one::<String>("memory")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| { warn!("Invalid duration specified, using default 60s"); 60 });
        let samples = analyzer.monitor_memory(duration, "memory_plot.png")?;
        println!("Collected {} memory samples.", samples.len());
        executed = true;
    }

    if matches.get_flag("so_memory") {
        let so_libs = analyzer.analyze_so_memory()?;
        println!("SO Library Memory Analysis:");
        for so in &so_libs {
            println!("Name: {:<30} PSS: {:>8} KB  Private Dirty: {:>8} KB  Shared Dirty: {:>8} KB",
                so.name, so.pss, so.private_dirty, so.shared_dirty);
        }
        executed = true;
    }

    if !executed {
        analyzer.start_logcat()?;
    }

    Ok(())
}