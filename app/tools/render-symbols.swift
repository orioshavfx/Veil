// Renders SF Symbols into template PNGs for the menu bar icon.
// Usage: swift app/tools/render-symbols.swift <out-dir>
import AppKit

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
// name in SF Symbols -> file name
let symbols = [("shield", "tray-off"), ("shield.fill", "tray-on")]
// The menu bar is 22 pt high; render at 2x for Retina.
let canvas = NSSize(width: 44, height: 44)

for (symbol, file) in symbols {
    let config = NSImage.SymbolConfiguration(pointSize: 30, weight: .semibold)
    guard let image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
        .withSymbolConfiguration(config) else {
        fatalError("unknown symbol \(symbol)")
    }
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(canvas.width), pixelsHigh: Int(canvas.height),
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let size = image.size
    let origin = NSPoint(x: (canvas.width - size.width) / 2, y: (canvas.height - size.height) / 2)
    // Black on transparent: macOS recolors template images for the menu bar.
    image.isTemplate = false
    let tinted = NSImage(size: size, flipped: false) { rect in
        image.draw(in: rect)
        NSColor.black.set()
        rect.fill(using: .sourceAtop)
        return true
    }
    tinted.draw(in: NSRect(origin: origin, size: size))
    NSGraphicsContext.restoreGraphicsState()
    let png = rep.representation(using: .png, properties: [:])!
    try! png.write(to: URL(fileURLWithPath: "\(out)/\(file).png"))
    print("\(symbol) -> \(file).png")
}
