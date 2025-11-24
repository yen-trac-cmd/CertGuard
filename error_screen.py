from certguard_config import ErrorLevel, BYPASS_PARAM
from mitmproxy import http
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

color_schemes = {
        "Green":   {"bg": "#e6f9ec", "errorlevel_color": "#28a745"},
        "Blue":    {"bg": "#e6f2ff", "errorlevel_color": "#007bff"},
        "Yellow":  {"bg": "#fffbe6", "errorlevel_color": "#ffc107"},
        "Orange":  {"bg": "#fff4e6", "errorlevel_color": "#fd7e14"},
        "Red":     {"bg": "#ffe6e6", "errorlevel_color": "#dc3545"},
        "Maroon":  {"bg": "#f9e6ec", "errorlevel_color": "#800000"},
    }

def append_query_param(url, key, value):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[key] = value
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def error_screen(config, flow, token, color, violations, error_level):
    scheme = color_schemes.get(color, {"bg": "#f0f0f0", "errorlevel_color": "#666"})
    bg, errorlevel_color = scheme["bg"], scheme["errorlevel_color"]

    if error_level < ErrorLevel.FATAL.value:
        if config.token_mode == 'get':
            bypass_url = append_query_param(flow.request.pretty_url, BYPASS_PARAM, token)
            prompt= f"""
                <p>Are you sure you want to proceed?</p>
                <a href="{bypass_url}" class="btn">Proceed Anyway</a>
                """
        
        elif config.token_mode == 'post':
            prompt = f"""
                <p>Are you sure you want to proceed?</p>
                <form method="POST" action="{flow.request.pretty_url}">
                    <input type="hidden" name="{BYPASS_PARAM}" value="{token}">
                    <button type="submit">Proceed Anyway</button>
                </form>
            """
        
        elif config.token_mode == 'header':
            prompt = f"""
                <p>Are you sure you want to proceed?</p>
                <button id="approve-btn">Proceed Anyway</button>
                <noscript><p><b>JavaScript is required to bypass this warning.</b></p></noscript>
                """
            javascript = f"""
                <script>
                document.addEventListener("DOMContentLoaded", () => {{
                    const btn = document.getElementById("approve-btn");
                    if (btn) {{
                        btn.addEventListener("click", () => {{
                            fetch(window.location.href, {{
                                method: "POST",
                                headers: {{"X-{BYPASS_PARAM}": "{token}"}}
                            }}).then(() => window.location.reload());
                        }});
                    }}
                }});
                </script>
                """
    else:
        prompt = f"""
            <p><b>For your safety, Level-6 warnings cannot be bypassed.</b></p>
            """

    violations_html = '<br>'.join(v for v in violations if v)

    warning_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CertGuard Warning!</title>
    <style>
    body         {{ margin:0; font-family:Arial, sans-serif; background:{bg}; color:#333; }}
    .warning-box {{ max-width:700px; margin:10% auto; padding:30px; border:3px solid {errorlevel_color}; border-radius:12px; background:#fff; box-shadow:0 4px 12px rgba(0,0,0,0.15); }}
    h1           {{ color:{errorlevel_color}; margin-top:0; }}
    p            {{ font-size:1.1em; line-height:1.6; }}
    a.std        {{}}
    a.btn        {{ display:inline-block; padding:10px 15px; background:{errorlevel_color}; color:white; text-decoration:none; border-radius:4px; cursor:pointer; }}              
    </style>
    {javascript if config.token_mode == 'header' and error_level < ErrorLevel.FATAL.value else ""}
    </head>
    <body>
    <div class="warning-box">
        <h1>Level {error_level} Warning</h1>
        <p>{violations_html}</p>
        <p>The domain <strong>{flow.request.pretty_host}</strong> violated one or more safety checks!</p>
        {prompt}
    </div>
    </body>
</html>
        """
       
    warning_html = "\n".join(line.rstrip() for line in warning_html.splitlines() if line.strip())
    flow.response = http.Response.make(615, warning_html, {"Content-Type": "text/html", "Cache-Control": "no-cache, no-store, must-revalidate", "Expires": "0"} )