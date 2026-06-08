import re
import hashlib
import tkinter as tk
from tkinter import scrolledtext


def analyze_header():

    email_header = header_input.get("1.0", tk.END)

    result_box.delete("1.0", tk.END)

    ip_addresses = re.findall(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        email_header
    )

    result_box.insert(tk.END, "IP Addresses Found:\n")

    if ip_addresses:
        for ip in ip_addresses:
            result_box.insert(tk.END, ip + "\n")
    else:
        result_box.insert(tk.END, "No IP Found\n")

    spf_result = re.search(r'spf=(\w+)', email_header)
    dkim_result = re.search(r'dkim=(\w+)', email_header)
    dmarc_result = re.search(r'dmarc=(\w+)', email_header)

    result_box.insert(tk.END, "\nAuthentication Results:\n")

    if spf_result:
        result_box.insert(
            tk.END,
            "SPF: " + spf_result.group(1) + "\n"
        )
    else:
        result_box.insert(tk.END, "SPF: Not Found\n")

    if dkim_result:
        result_box.insert(
            tk.END,
            "DKIM: " + dkim_result.group(1) + "\n"
        )
    else:
        result_box.insert(tk.END, "DKIM: Not Found\n")

    if dmarc_result:
        result_box.insert(
            tk.END,
            "DMARC: " + dmarc_result.group(1) + "\n"
        )
    else:
        result_box.insert(tk.END, "DMARC: Not Found\n")

    hash_value = hashlib.sha256(
        email_header.encode()
    ).hexdigest()

    result_box.insert(tk.END, "\nSHA-256 Hash:\n")
    result_box.insert(tk.END, hash_value)


def generate_report():

    report_content = result_box.get("1.0", tk.END)

    with open(
        "forensic_report.txt",
        "w",
        encoding="utf-8"
    ) as report:

        report.write(
            "=================================\n"
        )
        report.write(
            "EMAIL HEADER FORENSIC REPORT\n"
        )
        report.write(
            "=================================\n\n"
        )

        report.write(report_content)

    result_box.insert(
        tk.END,
        "\n\nReport saved as forensic_report.txt"
    )


window = tk.Tk()

window.title("Email Header Forensic Tool")
window.geometry("900x700")


title_label = tk.Label(
    window,
    text="Email Header Analysis Tool",
    font=("Arial", 18, "bold")
)

title_label.pack(pady=10)


header_input = scrolledtext.ScrolledText(
    window,
    width=90,
    height=15
)

header_input.pack(pady=10)


analyze_button = tk.Button(
    window,
    text="Analyze Header",
    font=("Arial", 12, "bold"),
    command=analyze_header
)

analyze_button.pack(pady=5)


report_button = tk.Button(
    window,
    text="Generate Report",
    font=("Arial", 12, "bold"),
    command=generate_report
)

report_button.pack(pady=5)


result_box = scrolledtext.ScrolledText(
    window,
    width=90,
    height=15
)

result_box.pack(pady=10)


window.mainloop()