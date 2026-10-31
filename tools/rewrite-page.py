
# -*- coding: utf-8 -*-
import io
p = r"S:\ZWorker\NetWatch\src\NetWatch\MainWindow.xaml"
with io.open(p, encoding="utf-8") as f: t = f.read()

start = t.find('            <!-- ========== 4. 网络体检 ========== -->')
end_marker = '            <!-- ========== 5. 监听端口 ========== -->'
end = t.find(end_marker)
assert start > 0 and end > start, (start, end)

new_block = io.open(r"S:\ZWorker\NetWatch\tools\netcheck-page.xaml", encoding="utf-8").read()
t = t[:start] + new_block + t[end:]
with io.open(p, "w", encoding="utf-8", newline="\n") as f: f.write(t)
print("netcheck page rewritten")
