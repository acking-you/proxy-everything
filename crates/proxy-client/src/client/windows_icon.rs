//! Windows executable icon extraction for the TUN process picker.

use std::ffi::c_void;
use std::io::Cursor;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
    DeleteDC, DeleteObject, GetDC, ReleaseDC, SelectObject,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::UI::Shell::{SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON, SHGetFileInfoW};
use windows_sys::Win32::UI::WindowsAndMessaging::{DI_NORMAL, DestroyIcon, DrawIconEx};

const ICON_SIZE: u32 = 32;

/// Return the shell icon for an executable as PNG bytes.
pub(super) fn executable_icon_png(path: &Path) -> Option<Vec<u8>> {
    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut file_info = SHFILEINFOW::default();
    // SAFETY: `wide_path` is NUL terminated, `file_info` has the exact API
    // layout, and a successful call transfers an icon handle that is destroyed
    // below after rendering.
    let result = unsafe {
        SHGetFileInfoW(
            wide_path.as_ptr(),
            FILE_ATTRIBUTE_NORMAL,
            &mut file_info,
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        )
    };
    if result == 0 || file_info.hIcon.is_null() {
        return None;
    }

    let rgba = render_icon_rgba(file_info.hIcon);
    // SAFETY: `hIcon` is owned by this SHGetFileInfoW result and no longer used.
    unsafe { DestroyIcon(file_info.hIcon) };
    encode_png(&rgba?)
}

fn render_icon_rgba(icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON) -> Option<Vec<u8>> {
    let bitmap_info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: ICON_SIZE as i32,
            // A negative height creates a top-down DIB, matching Flutter's row
            // orientation without a second vertical copy.
            biHeight: -(ICON_SIZE as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            biSizeImage: ICON_SIZE * ICON_SIZE * 4,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bits: *mut c_void = ptr::null_mut();

    // SAFETY: every GDI handle is checked before use, selected objects are
    // restored before deletion, and all acquired handles are released exactly
    // once on every path below.
    unsafe {
        let screen = GetDC(ptr::null_mut());
        if screen.is_null() {
            return None;
        }
        let memory = CreateCompatibleDC(screen);
        if memory.is_null() {
            ReleaseDC(ptr::null_mut(), screen);
            return None;
        }
        let bitmap = CreateDIBSection(
            memory,
            &bitmap_info,
            DIB_RGB_COLORS,
            &mut bits,
            ptr::null_mut(),
            0,
        );
        if bitmap.is_null() || bits.is_null() {
            if !bitmap.is_null() {
                DeleteObject(bitmap);
            }
            DeleteDC(memory);
            ReleaseDC(ptr::null_mut(), screen);
            return None;
        }
        let previous = SelectObject(memory, bitmap);
        ptr::write_bytes(bits, 0, (ICON_SIZE * ICON_SIZE * 4) as usize);
        let drawn = DrawIconEx(
            memory,
            0,
            0,
            icon,
            ICON_SIZE as i32,
            ICON_SIZE as i32,
            0,
            ptr::null_mut(),
            DI_NORMAL,
        ) != 0;
        let bgra =
            std::slice::from_raw_parts(bits.cast::<u8>(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        let mut rgba = bgra.to_vec();
        for pixel in rgba.chunks_exact_mut(4) {
            pixel.swap(0, 2);
        }
        SelectObject(memory, previous);
        DeleteObject(bitmap);
        DeleteDC(memory);
        ReleaseDC(ptr::null_mut(), screen);
        drawn.then_some(rgba)
    }
}

fn encode_png(rgba: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(Cursor::new(&mut output), ICON_SIZE, ICON_SIZE);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(rgba).ok()?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_executable_icon_is_encoded_as_png() {
        let icon = executable_icon_png(&std::env::current_exe().unwrap())
            .expect("Windows shell should provide an executable icon");
        assert_eq!(&icon[..8], b"\x89PNG\r\n\x1a\n");
    }
}
