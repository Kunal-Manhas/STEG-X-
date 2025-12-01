import argparse
import os
import sys
from stegano import lsb
from PIL import Image
from termcolor import colored


def print_banner():
    print("""
        🕵️‍♂️ STEG-X: ADVANCED STEGANOGRAPHY TOOL (TEXT-IN-IMAGE)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 USAGE:
  python stageno.py <command> [options]

🛠️ AVAILABLE COMMANDS:
  🫥  hide       Hide secret text inside an image
  🔓  extract    Extract hidden text from a stego image
  🔍  detect     Analyze an image for possible LSB steganography

📖 EXAMPLES:
  💬 Hide a message:
      python stageno.py hide input.png output.png "The code is 42"

  📤 Extract a hidden message:
      python stageno.py extract stego_image.png

  🧠 Detect possible steganography:
      python stageno.py detect suspect.jpg

🎯 TIPS:
  ✅ Use high-quality PNG images for better results
  🧪 Detection uses entropy analysis of pixel LSBs

📜 FLAGS:
  -h, --help     Show this help message and exit

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


""")



def print_success(msg):
    print(colored(f"[✔] {msg}", "green"))

def print_info(msg):
    print(colored(f"[i] {msg}", "cyan"))

def print_warning(msg):
    print(colored(f"[!] {msg}", "yellow"))

def print_error(msg):
    print(colored(f"[✘] {msg}", "red"))

# core part where we are usind the stegano library to hide and extract text from images

def hide_text(input_image, output_image, secret_text):
    try:
        secret_image = lsb.hide(input_image, secret_text)
        secret_image.save(output_image)
        print_success(f"Secret text hidden in: {output_image}")
    except Exception as e:
        print_error(f"Failed to hide text: {e}")

def extract_text(stego_image):
    try:
        hidden_text = lsb.reveal(stego_image)
        if hidden_text:
            print_success("Hidden text found:")
            print(colored(hidden_text, "magenta"))
        else:
            print_warning("No hidden text found or image not supported.")
    except Exception as e:
        print_error(f"Extraction failed: {e} ")
        print_error("Ensure the image is a valid stego image with hidden text.")

def detect_lsb(image_path):
    try:
        with Image.open(image_path) as img:
            # Ensure a consistent mode
            if img.mode not in ("RGB", "RGBA"):
                img = img.convert("RGB")

            pixels = list(img.getdata())

            # Sample up to 2000 pixels
            sample = pixels[:min(len(pixels), 2000)]

            # Take LSBs of the red channel
            lsb_bits = [p[0] & 1 for p in sample]

            ones = sum(lsb_bits)
            total = len(lsb_bits)
            zeros = total - ones

            if total == 0:
                print_warning("No pixels to analyze.")
                return

            print_info(f"Sampled pixels: {total}")
            print_info(f"LSB 1s: {ones}, LSB 0s: {zeros}")

            ratio = ones / total
            print_info(f"Ratio of 1s: {ratio:.3f}")

            # 1) Almost perfectly balanced (around 50–50) → suspicious
            if 0.45 <= ratio <= 0.55:
                print_success(
                    "Suspicious: LSBs look very balanced/random. Possible hidden data."
                )

            # 2) Extremely biased (almost all 0s or all 1s) → also suspicious
            elif ratio <= 0.1 or ratio >= 0.9:
                print_success(
                    "Suspicious: LSBs are extremely biased. Possible artificial manipulation."
                )

            # 3) Everything else → not clearly suspicious
            else:
                print_info(
                    "No obvious LSB hidden data found (heuristic only, not a guarantee)."
                )

    except Exception as e:
        print_error(f"Error in detection: {e}")

    try:
        with Image.open(image_path) as img:
            pixels = list(img.getdata())
            
            lsb_data = ''.join(str(pixel[0] & 1) for pixel in pixels[:1000])

            ones = lsb_data.count('1')
            zeros = lsb_data.count('0')
            total = ones + zeros

            if total == 0:
                print_warning("No pixels to analyze.")
                return 

            print_info(f"LSB pattern: 1s = {ones}, 0s = {zeros}")

            ratio = ones / total 

            # Heuristic 1: very balanced -> suspicious
            if abs(ones - zeros) < total * 0.05:
                print_success("Suspicious LSB manipulation detected (balanced distribution).")

            # Heuristic 2: extremely biased -> also suspicious
            elif ratio <= 0.1 or ratio >= 0.9:
                print_success("Suspicious: LSBs are extremely biased. Possible artificial manipulation.")

            else:
                print_info("No obvious LSB hidden data found (heuristic only, not a guarantee).")

    except Exception as e:
        print_error(f"Error in detection: {e}")


def validate_image(path):
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError("File does not exist.")
    try:
        with Image.open(path) as img:
            if img.format not in ['PNG', 'JPEG', 'JPG']:
                raise argparse.ArgumentTypeError("Unsupported image format. Use PNG or JPG.")
    except Exception:
        raise argparse.ArgumentTypeError("Invalid image file.")
    return path

#  this is to handle the CLI of the tool 

def main():
    parser = argparse.ArgumentParser(
        description="Steg-X: Hide and detect secret messages in images",
        add_help=True,
        usage="python stageno.py <command> [options]"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Hide command
    hide_parser = subparsers.add_parser("hide", help="Hide secret text in an image")
    hide_parser.add_argument("input", type=validate_image, help="Input image path")
    hide_parser.add_argument("output", help="Output image path (.png recommended)")
    hide_parser.add_argument("text", help="Secret message to hide")



    # Extract command
    extract_parser = subparsers.add_parser("extract", help="Extract secret text from image")
    extract_parser.add_argument("image", type=validate_image, help="Stego image path")

    # Detect command
    detect_parser = subparsers.add_parser("detect", help="Detect if LSB steganography is used")
    detect_parser.add_argument("image", type=validate_image, help="Image path to analyze")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        sys.exit(0)

    if args.command == "hide":
        hide_text(args.input, args.output, args.text)
    elif args.command == "extract":
        extract_text(args.image)
    elif args.command == "detect":
        detect_lsb(args.image)

# sir here is the main function to run the script (calling the main function)

if __name__ == "__main__":
    main()

