pub use samply_api::debugid::{CodeId, DebugId};
use samply_api::samply_symbols::{
    CandidatePathInfo, FileAndPathHelper, FileAndPathHelperResult, FileLocation, LibraryInfo,
    OptionallySendFuture, SymbolManager,
};
use samply_api::Api;
use std::fs::File;
use std::path::PathBuf;

pub async fn query_api(request_url: &str, request_json: &str, symbol_directory: PathBuf) -> String {
    let helper = Helper { symbol_directory };
    let symbol_manager = SymbolManager::with_helper(helper);
    let api = Api::new(&symbol_manager);
    api.query_api(request_url, request_json).await
}

struct Helper {
    symbol_directory: PathBuf,
}

impl FileAndPathHelper for Helper {
    type F = memmap2::Mmap;

    fn get_candidate_paths_for_debug_file(
        &self,
        library_info: &LibraryInfo,
    ) -> FileAndPathHelperResult<Vec<CandidatePathInfo>> {
        let debug_name = match library_info.debug_name.as_deref() {
            Some(debug_name) => debug_name,
            None => return Ok(Vec::new()),
        };

        let mut paths = vec![];

        // Check .so.dbg files in the symbol directory.
        if debug_name.ends_with(".so") {
            let debug_debug_name = format!("{debug_name}.dbg");
            paths.push(CandidatePathInfo::SingleFile(FileLocation::LocalFile(
                self.symbol_directory.join(debug_debug_name),
            )));
        }

        // And dSYM packages.
        if !debug_name.ends_with(".pdb") {
            paths.push(CandidatePathInfo::SingleFile(FileLocation::LocalFile(
                self.symbol_directory
                    .join(format!("{debug_name}.dSYM"))
                    .join("Contents")
                    .join("Resources")
                    .join("DWARF")
                    .join(debug_name),
            )));
        }

        // And Breakpad .sym files.
        if let Some(debug_id) = library_info.debug_id {
            paths.push(CandidatePathInfo::SingleFile(FileLocation::LocalFile(
                self.symbol_directory
                    .join(debug_name)
                    .join(debug_id.breakpad().to_string())
                    .join(format!("{}.sym", debug_name.trim_end_matches(".pdb"))),
            )));
        }

        // Finally, the file itself.
        paths.push(CandidatePathInfo::SingleFile(FileLocation::LocalFile(
            self.symbol_directory.join(debug_name),
        )));

        // For macOS system libraries, also consult the dyld shared cache.
        if self.symbol_directory.starts_with("/usr/")
            || self.symbol_directory.starts_with("/System/")
        {
            if let Some(dylib_path) = self.symbol_directory.join(debug_name).to_str() {
                paths.extend(
                    self.get_dyld_shared_cache_paths(None)
                        .unwrap()
                        .into_iter()
                        .map(|dyld_cache_path| CandidatePathInfo::InDyldCache {
                            dyld_cache_path,
                            dylib_path: dylib_path.to_string(),
                        }),
                );
            }
        }

        Ok(paths)
    }

    fn get_dyld_shared_cache_paths(
        &self,
        _arch: Option<&str>,
    ) -> FileAndPathHelperResult<Vec<FileLocation>> {
        Ok(vec![
            FileLocation::LocalFile("/System/Library/dyld/dyld_shared_cache_arm64e".into()),
            FileLocation::LocalFile("/System/Library/dyld/dyld_shared_cache_x86_64h".into()),
            FileLocation::LocalFile("/System/Library/dyld/dyld_shared_cache_x86_64".into()),
        ])
    }

    fn load_file(
        &self,
        location: FileLocation,
    ) -> std::pin::Pin<Box<dyn OptionallySendFuture<Output = FileAndPathHelperResult<Self::F>> + '_>>
    {
        Box::pin(async {
            let mut path = match location {
                FileLocation::LocalFile(path) => path,
                _ => unimplemented!(),
            };

            if !path.starts_with(&self.symbol_directory) {
                // See if this file exists in self.symbol_directory.
                // For example, when looking up object files referenced by mach-O binaries,
                // we want to take the object files from the symbol directory if they exist,
                // rather than from the original path.
                if let Some(filename) = path.file_name() {
                    let redirected_path = self.symbol_directory.join(filename);
                    if std::fs::metadata(&redirected_path).is_ok() {
                        // redirected_path exists!
                        eprintln!("Redirecting {:?} to {:?}", &path, &redirected_path);
                        path = redirected_path;
                    }
                }
            }

            eprintln!("Reading file {:?}", &path);
            let file = File::open(&path)?;
            Ok(unsafe { memmap2::MmapOptions::new().map(&file)? })
        })
    }

    fn get_candidate_paths_for_binary(
        &self,
        library_info: &LibraryInfo,
    ) -> FileAndPathHelperResult<Vec<CandidatePathInfo>> {
        let name = match library_info.name.as_deref() {
            Some(name) => name,
            None => return Ok(Vec::new()),
        };

        let mut paths = vec![];

        // Start with the file itself.
        paths.push(CandidatePathInfo::SingleFile(FileLocation::LocalFile(
            self.symbol_directory.join(name),
        )));

        // For macOS system libraries, also consult the dyld shared cache.
        if self.symbol_directory.starts_with("/usr/")
            || self.symbol_directory.starts_with("/System/")
        {
            if let Some(dylib_path) = self.symbol_directory.join(name).to_str() {
                paths.extend(
                    self.get_dyld_shared_cache_paths(None)
                        .unwrap()
                        .into_iter()
                        .map(|dyld_cache_path| CandidatePathInfo::InDyldCache {
                            dyld_cache_path,
                            dylib_path: dylib_path.to_string(),
                        }),
                );
            }
        }

        Ok(paths)
    }
}
