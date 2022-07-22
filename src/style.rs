use indicatif::{ProgressBar, ProgressStyle};

pub fn get_progressbar(n_items: u64, redraw_delta: u64) -> ProgressBar {
    let bar = ProgressBar::new(n_items);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}"),
    );
    bar.set_draw_delta(redraw_delta);
    bar
}
