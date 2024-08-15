<p align="center">
   <img src="bet.png" width="100" height="100">
</p>

# 🕵️‍♂️ DOMClob: DOM Clobbering Vulnerability Scanner

DOMClob is a powerful tool designed to identify and exploit potential DOM (Document Object Model) clobbering vulnerabilities in web applications. DOM clobbering involves manipulating the DOM to override or "clobber" global JavaScript objects, potentially leading to client-side security vulnerabilities such as cross-site scripting (XSS).

**DOM Clobbering by nature highly intrsuive. Do not proceed until you have a clear and consise understanding of the vulnerability and impact. While this tool is essentially fancy pattern matching, blindly running the generated PoC is not recommended unless you know what you're doing. Happy Hacking :)**

## 🚀 Features

- 🔍 Automated scanning of single or multiple URLs
- 🧪 Tests various DOM clobbering payloads
- 📊 Detailed vulnerability reporting
- 🛠️ Proof of Concept (PoC) generation
- 📈 Progress bar for multiple URL scans
- 🎨 Colorized console output

## 📦 Installation

1. Ensure you have Go installed on your system.
2. Clone this repository: 

```
git clone https://github.com/queencitycyber/DOMCLOB
cd DOMCLOB
go mod init domclob.go
go mod tidy
go build .
```

## 🔧 Usage

Public Firing Range: [https://public-firing-range.appspot.com/](https://public-firing-range.appspot.com/)


### Help Menu

```
NAME:
   domclob - Scan for DOM Clobbering vulnerabilities

USAGE:
   domclob [global options] command [command options]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --url value, -u value   Single URL to test
   --file value, -f value  File containing URLs to test
   --poc                   Output PoC details (default: false)
   --proof                 Output proof of vulnerable code (default: false)
   --help, -h              show help

```

### Example Run - Provide Proof

```
./domclob.go --url https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/innerHtml --proof
 100% |████████████| (1/1, 8 it/min)        
URL: https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/innerHtml
Vulnerable: Yes
Details:
Potential DOM clobbering vector found in script
Proof:
Vulnerable pattern: .innerHTML
--------------------------------------------------------------------------------
Results saved to dom_clobbering_results.json
```

### Example Run - Provide PoC
```
./domclob.go --url https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/innerHtml --poc
 100% |████████████| (1/1, 8 it/min)        
URL: https://public-firing-range.appspot.com/dom/toxicdom/document/cookie_set/innerHtml
Vulnerable: Yes
Details:
Potential DOM clobbering vector found in script
PoC:
[SNIP]

// Modified script to demonstrate vulnerability:
var div = document.createElement('div');
document.body.appendChild(div);
div.innerHTML = '<img src=x onerror=alert("DOM Clobbering vulnerability")>';
// Optionally, you can replace the above line with the vulnerable part of the original script

--------------------------------------------------------------------------------
Results saved to dom_clobbering_results.json
```

### Single URL Scan
```
./domclob --url https://example.com
```

### Multiple URL Scan
```
./domclob --file urls.txt
```

### Include PoC Commands
```
./domclob --url https://example.com --poc
```

### Include Proof of Vulnerable Code
```
./domclob --url https://example.com --proof
```

## 🔬 Methodology

### 1. Automated Scanning
The tool performs the following steps:
- Fetches the target URL(s)
- Analyzes the HTML content for potential DOM clobbering vectors
- Tests various DOM clobbering payloads
- Generates a detailed report of findings

### 2. Manual Verification
For each potentially vulnerable URL:
1. Open the URL in a browser
2. Open the browser's developer console
3. Inject test payloads into user input fields or URL parameters
4. Check for unexpected behavior or script execution

### 3. DOM Clobbering Payload Testing
The tool tests various payloads, including:
```html
<a id="x"><a id="x"><a id="x">
<form id="x"><form id="x"><form id="x">
<a id="x"><a id="x" name="y">
<img id="x"><img id="x"><img id="x">
<a id="innerHTML"><a id="innerHTML" name="y">
```

### 4. Identifying Vulnerable JavaScript
The scanner looks for JavaScript that uses:

* .innerHTML
* .outerHTML
* .textContent
* .innerText
* document.write()

## 📊 Results

The tool outputs a table with vulnerable URLs, details, and optional PoC commands
For manual testing, document:

The URL tested
The payload used
The observed behavior (e.g., unexpected script execution, DOM manipulation)


Results are saved in JSON format for further analysis

## 💡 Tips & Tricks

1. **URL Parameter Testing**: Try injecting payloads via URL parameters:

```
https://target.com/page?param=<a id="x"><a id="x"><a id="x">
```

2. **Combine with XSS**: DOM Clobbering can sometimes be combined with XSS for more severe impacts:

```html
<a id="defaultMessage"><a id="defaultMessage" name="innerHTML" href="javascript:alert(1)">
```

3. **Check Global Objects**: Look for JavaScript that uses global objects without proper checks:

```js
javascriptCopyif (window.config) {
  // Potentially vulnerable
}
```

4. Prototype Pollution: DOM Clobbering can sometimes lead to prototype pollution:

```html
htmlCopy<a id="__proto__"><a id="__proto__" name="vulnerable" href="true">
```


