use clap::{value_parser, Arg, ArgAction, Command};
use dialoguer::Confirm;
use image_hasher::{HashAlg, Hasher, HasherConfig, ImageHash};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use sha256::try_digest;
use path_absolutize::*;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Duration;
use serde_json::json;
use image;

fn default_style_factory() -> ProgressStyle {
    ProgressStyle::with_template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} [{per_sec:7}] {spinner:4.yellow} : {msg}").unwrap().tick_chars("/|\\- ")
}

fn hash_alg_option(opt: String) -> HashAlg {
    match opt.as_str() {
        "mean" => HashAlg::Mean,
        "grad" => HashAlg::Gradient,
        "vgrad" => HashAlg::VertGradient,
        "dgrad" => HashAlg::DoubleGradient,
        "block" => HashAlg::Blockhash,
        _ => HashAlg::Mean,
    }
}

fn hash_with_imagehasher(path: &Path, hasher: &Hasher) -> Option<String> {
    match image::open(path) {
        Ok(image) => {
            Some(hasher.hash_image(&image).to_base64())},
        Err(_) => {
            println!("Unable to open image file: {:?}", &path);
            None
        },
    }
}

fn hash_with_imagehasher_return_hash(path: &Path, hasher: &Hasher) -> Option<ImageHash> {
    match image::open(path) {
        Ok(image) => {
            Some(hasher.hash_image(&image))},
        Err(_) => {
            println!("Unable to open image file: {:?}", &path);
            None
        },
    }
}

fn hash_and_compare_dist(path: &Path, hash: ImageHash, hasher: &Hasher) -> Option<(u32,PathBuf)> {
    match image::open(path) {
        Ok(image) => {
            let hash2 = hasher.hash_image(&image);
            Some((hash.dist(&hash2), path.to_path_buf()))
        },
        Err(_) => {
            println!("Unable to open image file: {:?}", &path);
            None
        },
    }
}

fn main() {
    let matches = Command::new("Image Duplicate Finder")
        .version("1.0")
        .author("Your Name <you@example.com>")
        .about("Finds duplicate image files in a directory")
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .value_name("PATH")
                .help("Sets the path to search for image files")
                // .takes_value(true)
                .default_value(".")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("parallelism")
                .short('j')
                .long("parallelism")
                .value_name("PARALLELISM")
                .help("Sets the maximum number of threads to use for searching and hashing")
                // .takes_value(true)
                .default_value("0")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("extensions")
                .short('e')
                .long("extensions")
                .value_name("EXTENSIONS")
                .help("Sets the image file extensions to search for")
                .default_value("jpg,jpeg,png,webp")
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("remove")
                .short('r')
                .long("remove")
                .help("Remove duplicate files")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .help("Forces removal of duplicate files")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("algorithm")
                .short('a')
                .long("algorithm")
                .value_name("ALGORITHM")
                .help("Sets the hashing algorithm to use")
                .default_value("mean")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("use_imagehash")
                .short('i')
                .long("use-imagehash")
                .help("Use imagehash library instead of sha256")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("hash_size")
                .short('s')
                .long("hash-size")
                .value_name("HASH_SIZE")
                .help("Sets the hash size to use for imagehash")
                .default_value("8")
                .value_parser(value_parser!(u32)),
        ).arg(
            Arg::new("output_file").short('o').long("output-file").value_name("OUTPUT_FILE").required(false).help("Sets the output file to save a list of duplicate files and their full paths, will not save by default.").value_parser(value_parser!(PathBuf))
        ).arg(
            Arg::new("similar-to").short('t').long("similar-to").value_name("SIMILAR_TO").required(false).help("Sets the file to compare to, will not compare by default.").value_parser(value_parser!(PathBuf))
        ).arg(
            Arg::new("slice_size").short('l').long("slice-size").value_name("SLICE_SIZE").required(false).help("Sets the number of files to return, will not return by default.").value_parser(value_parser!(i32))
        )
        .get_matches();

    let path: &Path = Path::new(matches.get_one::<PathBuf>("path").unwrap().into());
    let parallelism_limit: u32 = matches.get_one::<u32>("parallelism").unwrap().clone();
    let extensions: Vec<String> = matches
        .get_many::<String>("extensions")
        .unwrap()
        .into_iter()
        .map(|x| x.to_lowercase())
        .collect::<Vec<String>>();
    let similar_to: Option<&PathBuf> = matches.try_get_one::<PathBuf>("similar-to").unwrap_or(None);
    let remove_duplicates: bool = matches.get_flag("remove");
    let force: bool = matches.get_flag("force");
    let use_imagehash: bool = matches.get_flag("use_imagehash");
    let hash_size: u32 = matches.get_one::<u32>("hash_size").unwrap().clone();
    let alg_opt: String = matches.get_one::<String>("algorithm").unwrap().clone();
    let slice_size: &i32 = matches.try_get_one::<i32>("slice_size").unwrap_or(Some(&(0 as i32))).unwrap();

    let output_file = matches.try_get_one::<PathBuf>("output_file").unwrap_or(None);

    if output_file.is_some() & remove_duplicates {
        println!("Cannot remove duplicates and save output file at the same time.");
        return;
    }

    let pb = ProgressBar::new_spinner()
        .with_message("Searching for image files...")
        .with_style(
            ProgressStyle::default_spinner()
                .tick_chars("/|\\- ")
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
    pb.enable_steady_tick(Duration::from_millis(50));

    let image_files: Vec<PathBuf> =
        get_image_files(&path, &extensions, parallelism_limit as usize, &pb);

    pb.finish_and_clear();

    let mut file_hashes: Vec<String> = vec![];
    if use_imagehash & similar_to.is_none() {
        let hasher = HasherConfig::new()
            .hash_size(hash_size, hash_size)
            .hash_alg(hash_alg_option(alg_opt))
            .to_hasher();
        let temp_hashes: Vec<String> = image_files
            .par_iter()
            .with_max_len(parallelism_limit as usize)
            .progress_with_style(default_style_factory())
            .filter_map(|path| hash_with_imagehasher(&path, &hasher))
            .collect();
        file_hashes.extend(temp_hashes);
    } else if similar_to.is_none(){
        let file_hashes_: Vec<String> = image_files
            .par_iter()
            .with_max_len(parallelism_limit as usize)
            .progress_with_style(default_style_factory())
            .map(|path| get_file_hash(&path, &pb))
            .collect();
        file_hashes.extend(file_hashes_);
    } else if use_imagehash {
        let hasher = HasherConfig::new()
            .hash_size(hash_size, hash_size)
            .hash_alg(hash_alg_option(alg_opt))
            .to_hasher();
        let similar_to = similar_to.unwrap();
        let hash = hash_with_imagehasher_return_hash(&similar_to, &hasher).unwrap();

        let mut temp_hashes: Vec<(u32,PathBuf)> = image_files
            .par_iter()
            .with_max_len(parallelism_limit as usize)
            .progress_with_style(default_style_factory())
            .filter_map(|path| hash_and_compare_dist(&path, hash.to_owned(), &hasher))
            .collect();
        temp_hashes.sort_by(|a, b| a.0.cmp(&b.0));
        temp_hashes.reverse();
        let temp_hashes_: Vec<String> = temp_hashes.iter().map(|x| format!("Dist: {} {}",x.0,x.1.as_os_str().to_str().unwrap())).collect();
        for idx in 0..(slice_size.abs()) {
            println!("{}", temp_hashes_[idx as usize]);
        }
        return;
    } else {
        panic!("Not implemented")
    }


    let mut hashes = HashSet::new();
    let mut hashes_files: HashMap<&String, Vec<PathBuf>> = HashMap::new();
    let mut removals_flagged: Vec<&PathBuf> = vec![];

    for (i, hash) in file_hashes.iter().enumerate() {
        let path = &image_files[i];
        let has_hash = hashes.contains(hash);
        if has_hash {
            if let Some(files) = hashes_files.get_mut(hash) {
                files.push(path.clone());
            } else {
                hashes_files.insert(hash, vec![path.clone()]);
            }
        } else {
            hashes.insert(hash);
            hashes_files.insert(hash, vec![path.clone()]);
        }
        if has_hash & !remove_duplicates {
            println!("Duplicate file: {:?}", path);
        } else if has_hash & remove_duplicates {
            println!("Adding duplicate file to flagged: {:?}", path);
            removals_flagged.push(path);
            // fs::remove_file(path).expect(format!("Unable to remove file: {:?}", path).as_str());
        } else {
            hashes.insert(hash);
        }
    }

    let total_removals = removals_flagged.len();
    let confirmation_message = format!(
        "Are you sure you want to remove {} files?",
        removals_flagged.len()
    );
    if force & remove_duplicates & (removals_flagged.len() > 0) {
        println!("Removing duplicate files... (forced)");
        let progress = ProgressBar::new(removals_flagged.len() as u64)
            .with_style(default_style_factory())
            .with_message("Removing duplicate files...");
        for path in removals_flagged {
            fs::remove_file(path).expect(format!("Unable to remove file: {:?}", path).as_str());
            progress.inc(1);
            progress.set_message(format!("Removed file: {:?}", path));
        }
    } else if !force & remove_duplicates & (removals_flagged.len() > 0) {
        if Confirm::new()
            .with_prompt(&confirmation_message)
            .wait_for_newline(true)
            .show_default(true)
            .interact()
            .unwrap()
        {
            let progress = ProgressBar::new(removals_flagged.len() as u64)
                .with_style(default_style_factory())
                .with_message("Removing duplicate files...");
            for path in removals_flagged {
                fs::remove_file(path).expect(format!("Unable to remove file: {:?}", path).as_str());
                progress.inc(1);
                progress.set_message(format!("Removed file: {:?}", path));
            }
            progress.finish_with_message(format!("Removed {} files", total_removals.clone()))
        }
    } else {
        println!("Not removing files...");
        match output_file {
            Some(out_file) => {
                println!("Saving output file: {:?}", out_file);
                let mut file = File::create(out_file).unwrap();
                let mut added_files: HashSet<String> = HashSet::new();
                let mut hash_dict: HashMap<String, Vec<PathBuf>> = HashMap::new();
                for (hash, files) in hashes_files {
                    if files.len() > 1 && !added_files.contains(hash) {
                        hash_dict.insert(hash.clone(), files.clone());
                        added_files.insert(hash.clone());
                    }
                }
                file.write_all(json!(hash_dict).to_string().as_bytes()).expect("Unable to write to output file.");
            },
            None => {
                println!("No output file specified, not saving output file.");
            }
        }
    }
}

fn get_image_files(
    path: &Path,
    image_extensions: &[String],
    parallelism_limit: usize,
    pb: &ProgressBar,
) -> Vec<PathBuf> {
    let mut image_files = Vec::new();

    let entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .into_iter()
        .map(|entry| entry.unwrap())
        .collect();

    let (dirs, files): (Vec<_>, Vec<_>) =
        entries.into_iter().partition(|entry| entry.path().is_dir());

    image_files.extend(
        files
            .into_par_iter()
            .with_max_len(parallelism_limit)
            .filter_map(|entry| {
                let path = entry.path();
                if let Some(extension) = path.extension() {
                    if image_extensions.contains(&extension.to_string_lossy().to_lowercase()) {
                        Some(path.as_path().absolutize().unwrap().to_path_buf())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .inspect(|_| pb.inc(1))
            .collect::<Vec<PathBuf>>(),
    );

    pb.set_length(image_files.len() as u64);

    for dir in dirs {
        image_files.extend(get_image_files(
            &dir.path(),
            image_extensions,
            parallelism_limit,
            pb,
        ));
    }

    image_files
}

fn get_file_hash(path: &Path, pb: &ProgressBar) -> String {
    let digest_ = try_digest(path);
    let digest = match digest_ {
        Ok(digest) => digest,
        Err(_) => {
            panic!("Unable to hash file: {:?}", &path);
        }
    };
    pb.inc(1);
    digest
}
