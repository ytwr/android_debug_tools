use std::process::Command;
use std::io::{BufRead, BufReader, Write};
use std::fs::File;
use std::time::{Duration, Instant};
use regex::Regex;
use anyhow::{Result, anyhow};
use clap::{Arg, Command as ClapCommand};
use serde::{Deserialize, Serialize};
use serde_json;
use plotters::prelude::*;

// 配置结构体
#[derive(Clone, Serialize, Deserialize)]
struct LogAnalyzerConfig {
    package_name: String,
    keyword_regex: String,
    output_file: Option<String>,
    sample_interval: u64, // 采样间隔（秒）
}

// 主分析工具结构体
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
struct ThreadInfo {
    tid: String,
    name: String,
    state: String,
    priority: String,
    user_time: String,
    system_time: String,
}

impl LogAnalyzer {
    fn new(config: LogAnalyzerConfig) -> Self {
        LogAnalyzer {
            config,
            adb_path: "adb".to_string(),
        }
    }

    // 实时日志采集与过滤
    fn start_logcat(&self) -> Result<()> {
        let re = Regex::new(&self.config.keyword_regex)?;
        let output = Command::new(&self.adb_path)
            .args(&["logcat", "-v", "time"])
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        let reader = BufReader::new(output.stdout.ok_or(anyhow!("Failed to get stdout"))?);

        if let Some(ref file_path) = self.config.output_file {
            let mut file = File::create(file_path)?;
            for line in reader.lines() {
                let line = line?;
                if re.is_match(&line) {
                    println!("Match found: {}", line);
                    writeln!(file, "{}", line)?;
                }
            }
        } else {
            for line in reader.lines() {
                let line = line?;
                if re.is_match(&line) {
                    println!("Match found: {}", line);
                }
            }
        }
        Ok(())
    }

    // 采集并绘制详细内存曲线
    fn monitor_memory(&self, duration: u64, output_image: &str) -> Result<Vec<MemorySample>> {
        let start = Instant::now();
        let mut samples = Vec::new();

        while start.elapsed().as_secs() < duration {
            let mem_info = self.get_memory_info()?;
            let sample = MemorySample {
                timestamp: start.elapsed().as_secs(),
                total_pss: parse_memory_value(&mem_info, "TOTAL PSS:")?,
                native_heap: parse_memory_value(&mem_info, "Native Heap:")?,
                dalvik_heap: parse_memory_value(&mem_info, "Dalvik Heap:")?,
                code: parse_memory_value(&mem_info, "Code:")?,
                stack: parse_memory_value(&mem_info, "Stack:")?,
                graphics: parse_memory_value(&mem_info, "Graphics:")?,
                private_dirty: parse_memory_value(&mem_info, "Private Dirty:")?,
                shared_dirty: parse_memory_value(&mem_info, "Shared Dirty:")?,
            };
            samples.push(sample);
            std::thread::sleep(Duration::from_secs(self.config.sample_interval));
        }

        self.plot_memory_curve(&samples, output_image)?;

        let json = serde_json::to_string_pretty(&samples)?;
        std::fs::write("memory_samples.json", json)?;

        let mut csv_file = File::create("memory_samples.csv")?;
        writeln!(csv_file, "timestamp,total_pss,native_heap,dalvik_heap,code,stack,graphics,private_dirty,shared_dirty")?;
        for sample in &samples {
            writeln!(csv_file, "{},{},{},{},{},{},{},{},{}",
                     sample.timestamp, sample.total_pss, sample.native_heap,
                     sample.dalvik_heap, sample.code, sample.stack,
                     sample.graphics, sample.private_dirty, sample.shared_dirty)?;
        }

        Ok(samples)
    }

    // 线程分析
    fn analyze_threads(&self) -> Result<Vec<ThreadInfo>> {
        let pid = self.get_pid()?;
        let output = Command::new(&self.adb_path)
            .args(&["shell", "ps", "-T", "-p", &pid])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get thread info: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let ps_output = String::from_utf8_lossy(&output.stdout);
        let mut threads = Vec::new();

        for line in ps_output.lines().skip(1) { // 跳过表头
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 9 {
                threads.push(ThreadInfo {
                    tid: fields[1].to_string(),        // Thread ID
                    name: fields[8].to_string(),       // Thread name
                    state: fields[4].to_string(),      // State (R, S, D, etc.)
                    priority: fields[5].to_string(),   // Priority
                    user_time: fields[6].to_string(),  // User time
                    system_time: fields[7].to_string(),// System time
                });
            }
        }

        // 输出到JSON
        let json = serde_json::to_string_pretty(&threads)?;
        std::fs::write("thread_info.json", json)?;

        // 输出到CSV
        let mut csv_file = File::create("thread_info.csv")?;
        writeln!(csv_file, "tid,name,state,priority,user_time,system_time")?;
        for thread in &threads {
            writeln!(csv_file, "{},{},{},{},{},{}",
                     thread.tid, thread.name, thread.state,
                     thread.priority, thread.user_time, thread.system_time)?;
        }

        Ok(threads)
    }

    // 绘制内存曲线图
    fn plot_memory_curve(&self, samples: &[MemorySample], output: &str) -> Result<()> {
        let root = BitMapBackend::new(output, (1200, 800)).into_drawing_area();
        root.fill(&WHITE)?;

        let max_pss = samples.iter().map(|s| s.total_pss).max().unwrap_or(1000) as f64 * 1.2;
        let max_time = samples.last().map(|s| s.timestamp).unwrap_or(1) as f64;

        let mut chart = ChartBuilder::on(&root)
            .caption("Detailed Memory Usage Over Time", ("sans-serif", 40).into_font())
            .margin(10)
            .x_label_area_size(30)
            .y_label_area_size(50)
            .build_cartesian_2d(0f64..max_time, 0f64..max_pss)?;

        chart.configure_mesh()
            .x_desc("Time (s)")
            .y_desc("Memory (KB)")
            .draw()?;

        let colors = [RED, BLUE, GREEN, CYAN, MAGENTA, YELLOW, BLACK, RGBColor(128, 0, 128)];
        let labels = [
            "Total PSS", "Native Heap", "Dalvik Heap", "Code",
            "Stack", "Graphics", "Private Dirty", "Shared Dirty"
        ];

        let data_fns: Vec<Box<dyn Fn(&MemorySample) -> (f64, f64)>> = vec![
            Box::new(|s| (s.timestamp as f64, s.total_pss as f64)),
            Box::new(|s| (s.timestamp as f64, s.native_heap as f64)),
            Box::new(|s| (s.timestamp as f64, s.dalvik_heap as f64)),
            Box::new(|s| (s.timestamp as f64, s.code as f64)),
            Box::new(|s| (s.timestamp as f64, s.stack as f64)),
            Box::new(|s| (s.timestamp as f64, s.graphics as f64)),
            Box::new(|s| (s.timestamp as f64, s.private_dirty as f64)),
            Box::new(|s| (s.timestamp as f64, s.shared_dirty as f64)),
        ];

        for (i, (color, label)) in colors.iter().zip(labels.iter()).enumerate() {
            let data: Vec<(f64, f64)> = samples.iter().map(|s| data_fns[i](s)).collect();
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
        Ok(())
    }

    // 获取内存信息
    fn get_memory_info(&self) -> Result<String> {
        let output = Command::new(&self.adb_path)
            .args(&["shell", "dumpsys", "meminfo", &self.config.package_name])
            .output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(anyhow!("Failed to get memory info: {}", String::from_utf8_lossy(&output.stderr)))
        }
    }

    // 获取进程PID
    fn get_pid(&self) -> Result<String> {
        let output = Command::new(&self.adb_path)
            .args(&["shell", "pidof", &self.config.package_name])
            .output()?;
        let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if pid.is_empty() { Err(anyhow!("Process not found")) } else { Ok(pid) }
    }
}

// 解析内存值
fn parse_memory_value(mem_info: &str, key: &str) -> Result<u64> {
    mem_info.lines()
        .find(|line| line.contains(key))
        .and_then(|line| {
            line.split_whitespace()
                .filter(|s| s.chars().all(|c| c.is_digit(10)))
                .next()
        })
        .and_then(|val| val.parse::<u64>().ok())
        .ok_or(anyhow!("Failed to parse {} value", key))
}

// 主函数
fn main() -> Result<()> {
    let matches = ClapCommand::new("Android Log Analyzer")
        .version("1.0")
        .arg(Arg::new("config")
            .short('c')
            .long("config")
            .value_name("CONFIG")
            .help("Path to JSON config file"))
        .arg(Arg::new("package")
            .short('p')
            .long("package")
            .value_name("PACKAGE")
            .help("Target package name"))
        .arg(Arg::new("regex")
            .short('r')
            .long("regex")
            .value_name("REGEX")
            .help("Keyword regex for log filtering"))
        .arg(Arg::new("memory")
            .short('m')
            .long("memory")
            .help("Monitor and plot memory usage")
            .value_name("DURATION")
            .default_missing_value("60"))
        .arg(Arg::new("threads")
            .short('t')
            .long("threads")
            .help("Analyze process threads")
            .action(clap::ArgAction::SetFalse))
        .get_matches();

    // 加载配置
    let config = if let Some(config_path) = matches.get_one::<String>("config") {
        let file = File::open(config_path)?;
        serde_json::from_reader(file)?
    } else {
        LogAnalyzerConfig {
            package_name: matches.get_one::<String>("package")
                .map(|s| s.to_string())
                .unwrap_or("com.example.app".to_string()),
            keyword_regex: matches.get_one::<String>("regex")
                .map(|s| s.to_string())
                .unwrap_or("ERROR|WARNING".to_string()),
            output_file: Some("filtered_logs.txt".to_string()),
            sample_interval: 1,
        }
    };

    let analyzer = LogAnalyzer::new(config);

    // 执行操作
    if matches.get_flag("threads") {
        let threads = analyzer.analyze_threads()?;
        println!("Thread Analysis:");
        for thread in &threads {
            println!("TID: {:<6} Name: {:<20} State: {:<2} Priority: {:<3} User Time: {:<6} System Time: {}",
                     thread.tid, thread.name, thread.state, thread.priority, thread.user_time, thread.system_time);
        }
    } else if matches.contains_id("memory") {
        let duration = matches.get_one::<String>("memory")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);
        analyzer.monitor_memory(duration, "memory_plot.png")?;
    } else {
        analyzer.start_logcat()?;
    }

    Ok(())
}