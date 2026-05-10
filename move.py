import re

with open('securefs_v2 (1).html', 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Extract COMPARE section
start_idx = html.find('      <!-- COMPARE -->')
end_idx = html.find('      <!-- PROJECTS -->')

compare_html = html[start_idx:end_idx]
html = html[:start_idx] + html[end_idx:]

# 2. Insert it into the landing page
# We want to insert it right before the closing div of the features-grid or landing-screen
# The landing-screen looks like:
#   <div class="features-grid">
#     ...
#     </div>
#   </div>
# </div>
# <div id="login-screen">
insert_target = '  </div>\n</div>\n\n<div id="login-screen">'
if insert_target in html:
    html = html.replace(insert_target, '  </div>\n' + compare_html + '</div>\n\n<div id="login-screen">')
else:
    print("Could not find insert target")

# 3. Remove nav item
nav_item = '<div class="nav-item" data-panel="compare" onclick="nav(this)"><span class="nav-icon">📊</span>Benchmarks</div>'
html = html.replace(nav_item, '')

# 4. Add initCompareCharts to showLanding
html = html.replace('function showLanding() {', 'function showLanding() {\n  setTimeout(initCompareCharts, 80);')

with open('securefs_v2 (1).html', 'w', encoding='utf-8') as f:
    f.write(html)
print("Done")
