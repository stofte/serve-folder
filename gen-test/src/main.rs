use std::{fmt::format, fs::{self, File}, io::{BufReader, BufWriter, Error, Write}, path::{Path, PathBuf}};

fn main() -> Result<(), std::io::Error> {
    let test_folder = "test-data";
    gen_fontawesome_html(test_folder, "svg-inline.html", true)?;
    gen_fontawesome_html(test_folder, "svg-img.html", false)?;
    Ok(())
}

fn gen_fontawesome_html(test_folder: &str, output_file: &str, embed_svg: bool) -> Result<(), std::io::Error> {
    let html = File::create(format!("{}\\{}", test_folder, output_file))?;
    let mut html = BufWriter::new(html);
    let svg_dir = PathBuf::from(format!("{}\\svgs", test_folder));
    let folders = get_entries(svg_dir, true)?;
    html.write_all("<!doctype html>\r\n<html>\r\n<body>\r\n<table>\r\n".as_bytes())?;
    let mut col_count = 0;
    for folder in folders {
        let files = get_entries(folder, false)?;
        for file in files {
            if col_count == 0 {
                html.write_all("  <tr>\r\n".as_bytes())?;
            }
            let fragment = get_html_fragment(&file, test_folder, embed_svg)?;
            let cell_html = format!("    <td>{}</td>\r\n", fragment);
            html.write_all(cell_html.as_bytes())?;
            col_count += 1;
            if col_count > 10 {
                html.write_all("  </tr>\r\n".as_bytes())?;
                col_count = 0;
            }
        }
    }
    html.write_all("</table>\r\n</body>\r\n</html>\r\n".as_bytes())?;
    Ok(())
}

fn get_entries(path: PathBuf, is_dir: bool) -> Result<Vec<PathBuf>, Error> {
    Ok(fs::read_dir(path)?
        .into_iter()
        .filter(|r| r.is_ok())
        .map(|r| r.unwrap().path())
        .filter(|r| if is_dir { r.is_dir() } else { r.is_file() })
        .collect())
}

fn get_html_fragment(file: &PathBuf, prefix: &str, embed_svg: bool) -> Result<String, Error> {
    use regex::Regex;
    let re = Regex::new(r#"viewBox="(\d+) (\d+) (\d+) (\d+)""#).unwrap();
    let svg = fs::read_to_string(file)?;
    let cap = re.captures(&svg).unwrap();
    let w_cap = cap.get(3).unwrap().as_str().parse::<f32>().unwrap();
    let h_cap = cap.get(4).unwrap().as_str().parse::<f32>().unwrap();
    let ratio = h_cap / w_cap;
    let width = 100;
    let height = (ratio * width as f32) as u32;
    let html: String;
    if embed_svg {
        let prefix = svg.find(" viewBox").unwrap();
        html = format!("{} style=\"width: {}px; height: {}px;\" {}",
            &svg[0..prefix], width, height, &svg[prefix..],
        );
    } else {
        let file_str = file.to_string_lossy().replace("\\", "/");
        let file_str = &file_str[prefix.len()+1..];
        html = format!("<img src=\"{}\" width=\"{}\" height=\"{}\">", file_str, width, height);
    }
    Ok(html)
}
