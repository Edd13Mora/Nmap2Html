
# 🌐 Nmap2HTML — Interactive Nmap Report Generator

> Convert your Nmap XML or GNMAP scan results into a **beautiful, responsive HTML dashboard** — directly from your browser.

<img width="996" height="516" alt="image" src="https://github.com/user-attachments/assets/4a643fc6-603b-49a5-87bf-f93a44a3cfc8" />
<img width="996" height="477" alt="image" src="https://github.com/user-attachments/assets/9b92e2cf-5c7e-4ad9-8dc3-a642c47e5c32" />
---

## ✨ Features

✅ **Web Interface (Flask)**
- Upload your Nmap XML (`-oX`) or GNMAP (`-oG`) file directly from the browser.
- Stylish Tailwind CSS upload form with clear scan instructions.

✅ **Professional HTML Report**
- Clean corporate white + mint UI design.  
- Fully **responsive**, readable on desktop or mobile.
- Smart **multi-select filters** (HTTP, SSH, FTP, RDP, MySQL).  
- **Live search**, **pagination**, and **Lucide icons** for readability.  
- Colored service categories with per-port tables.  
- Summary section with total hosts, open ports, and service counts.

✅ **Secure & Simple**
- Uploads sanitized (`secure_filename`).
- Supported formats: `.xml`, `.gnmap`.
- File size limit: 20 MB (default).
- Temporary file storage in `uploads/` and `reports/`.

✅ **Instant Report Download**
- Preview report in your browser.
- Download the generated HTML report with one click.

---

## 🧠 Quick Start

### 1. Clone or Download
```bash
git clone https://github.com/yourusername/nmap2html.git
cd nmap2html
```

### 2. Install Dependencies
```bash
pip install flask markupsafe
```

### 3. Run the App
```bash
python3 app.py
```

Then open your browser at  
👉 [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## ⚙️ Usage Instructions

### 🧾 Supported Input Files
- **Nmap XML output** (`-oX scan.xml`)
- **Nmap grepable output** (`-oG scan.gnmap`)

### 💻 Recommended Commands

| Type | Command |
|------|----------|
| XML | `sudo nmap -sS -sV -p- -T4 <target> -oX scan.xml` |
| GNMAP | `sudo nmap -sS -sV -p- -T4 <target> -oG scan.gnmap` |

> ⚠️ Always ensure you have permission before scanning production networks.

---

## 📂 Folder Structure

```
nmap2html/
│
├── app.py              # Main Flask app
├── uploads/            # Temporary upload storage
├── reports/            # Generated HTML reports
└── README.md
```

---

## 🖼️ Generated Report Example

A generated report includes:
- Blue & mint gradient header with your report title.  
- Summary cards (Hosts, Ports, Services).  
- Filter buttons for HTTP, SSH, FTP, RDP, MySQL.  
- Paginated host cards showing ports, states, products, and versions.  
- Responsive grid layout for smooth mobile/desktop use.

---

## 🛡️ Security Notes

- Only `.xml` and `.gnmap` files are accepted.  
- Filenames are sanitized before saving.  
- Files larger than 20 MB are automatically rejected.  
- Each uploaded file generates a unique UUID report filename.  
- Reports are stored locally under `reports/` — consider cleaning up old files periodically.

---

## 🚀 Example Demo (YouTube Description)

> **Nmap2HTML** — a clean, Flask-based tool to visualize your Nmap results like a professional dashboard.  
> Upload your scan file → get an interactive HTML report instantly.  
> No external dependencies, no JavaScript frameworks — just Flask + Tailwind + Lucide icons.

🎥 **Demo:**  
- Upload Nmap XML  
- See instant dashboard  
- Filter results  
- Download report  
---

## 🧩 Requirements

- Python 3.8+  
- Flask 3.x  
- markupsafe

Install:
```bash
pip install flask markupsafe
```

---

## 🧹 Optional Cleanup (Advanced)

To auto-delete reports older than 24 hours, you can add this simple cron job:
```bash
find /path/to/nmap2html/reports -type f -mtime +1 -delete
find /path/to/nmap2html/uploads -type f -mtime +1 -delete
```
---

## 🧑‍💻 Author
**Eddie Morra**   
---

### 💬 “Turn your raw Nmap scans into clean, client-ready dashboards.”
