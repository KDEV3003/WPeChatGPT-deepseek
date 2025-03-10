import functools
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai
import re
import threading
import json
import sys, os

# Windows
path = os.path.dirname(os.path.abspath(__file__)) + "\\Auto-WPeGPT_WPeace\\"
# MacOS
# path = os.path.dirname(os.path.abspath(__file__)) + "/Auto-WPeGPT_WPeace/"
sys.path.append(path)
import Auto_WPeGPT
from openai import OpenAI
# 是否使用中文提示
ZH_CN = True
# 设置 API key，如未设置也可通过环境变量 OPENAI_API_KEY 获取
# proxies 和 api_base 配置可根据需要打开或修改
# print("WPeChatGPT has appointed the proxy.")
# proxies = {'http': "http://127.0.0.1:7890", 'https': "http://127.0.0.1:7890"}
# openai.proxy = proxies
# openai.api_base = "https://api.deepseek.com"

client = OpenAI(api_key="", base_url="https://api.siliconflow.cn")

# 预编译正则，用于解析 JSON 输出
JSON_REGEX = re.compile(r"\{[^}]*?\}")

# WPeChatGPT 分析解释函数
class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        funcComment = getFuncComment(ea)
        if "---GPT_START---" in funcComment:
            if ZH_CN:
                print("当前函数已完成 WPeChatGPT:Explain 分析，请查看或清除注释后重试。@Sebao")
            else:
                print("The current function has already been analyzed by WPeChatGPT:Explain. Please check or remove the comment to re-analyze. @Sebao")
            return 0
        decompiler_output = ida_hexrays.decompile(ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # 中文提示
        if ZH_CN:
            query_text = (
                "你是网络安全专业教师，精通各种语言及不同架构的汇编和漏洞。"
                "下面是一个 C 语言伪代码函数，请分析其预期目的、参数作用、详细功能，以及函数逻辑，让学生们更清晰的理解。（回答前加'---GPT_START---'，结尾加'---GPT_END---'）\n"
                f"{decompiler_output}"
            )
        else:
            query_text = (
                "Analyze the following C pseudocode function, speculate on its usage, purpose, and detailed function, "
                "and finally suggest a new name for it. (Prepend '---GPT_START---' and append '---GPT_END---')\n"
                f"{decompiler_output}"
            )
        query_model_async(
            query_text,
            functools.partial(comment_callback, address=ea, view=v, cmtFlag=0, printFlag=0),
            0
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# WPeChatGPT 重命名变量函数
class RenameHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        decompiler_output = ida_hexrays.decompile(ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_text = (
            "Analyze the following C function:\n"
            f"{decompiler_output}\n"
            "Suggest better variable names in a JSON dictionary (keys are original names, values are the proposals). "
            "Do not include any explanation, only output the JSON dictionary."
        )
        query_model_async(
            query_text,
            functools.partial(rename_callback, address=ea, view=v),
            0
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# WPeChatGPT 使用python3对函数进行还原
class PythonHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        screen_ea = idaapi.get_screen_ea()
        lastAddr = idc.prev_head(idc.get_func_attr(screen_ea, idc.FUNCATTR_END))
        addrComment = getAddrComment(lastAddr)
        if "---GPT_Python_START---" in str(addrComment):
            if ZH_CN:
                print("当前函数已完成 WPeChatGPT:Python 分析，请查看或清除注释后重试。@Sebao")
            else:
                print("The current function has already been analyzed by WPeChatGPT:Python. Please check or remove the comment to re-analyze. @Sebao")
            return 0
        decompiler_output = ida_hexrays.decompile(screen_ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if ZH_CN:
            query_text = (
                "你是网络安全专业教师，精通各种语言及不同架构的汇编和漏洞。"
                "分析下面的 C 语言伪代码，并用 python3 代码还原。（回答前加'---GPT_Python_START---'，结尾加'---GPT_Python_END---'）\n"
                f"{decompiler_output}"
            )
        else:
            query_text = (
                "Analyze the following C pseudocode and restore it with python3 code. "
                "(Prepend '---GPT_Python_START---' and append '---GPT_Python_END---')\n"
                f"{decompiler_output}"
            )
        query_model_async(
            query_text,
            functools.partial(comment_callback, address=lastAddr, view=v, cmtFlag=1, printFlag=1),
            0
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# WPeChatGPT 尝试寻找函数漏洞
class FindVulnHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        funcComment = getFuncComment(ea)
        if "---GPT_VulnFinder_START---" in funcComment:
            if ZH_CN:
                print("当前函数已完成 WPeChatGPT:VulnFinder 分析，请查看或清除注释后重试。@Sebao")
            else:
                print("The current function has been analyzed by WPeChatGPT:VulnFinder. Please check or remove the comment to re-analyze. @Sebao")
            return 0
        decompiler_output = ida_hexrays.decompile(ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if ZH_CN:
            query_text = (
                "你是网络安全专业教师，精通各种语言及不同架构汇编和漏洞，查找下面 C 语言伪代码函数的存在的安全隐患或者漏洞并提出可能的利用方法最好用python写出poc验证脚本，让学生们更好的理解漏洞原理。。（回答前加'---GPT_VulnFinder_START---'，结尾加'---GPT_VulnFinder_END---'）\n"
                f"{decompiler_output}"
            )
        else:
            query_text = (
                "Find the vulnerability in the following C function and suggest a possible exploitation method. "
                "(Prepend '---GPT_VulnFinder_START---' and append '---GPT_VulnFinder_END---')\n"
                f"{decompiler_output}"
            )
        query_model_async(
            query_text,
            functools.partial(comment_callback, address=ea, view=v, cmtFlag=0, printFlag=2),
            0
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# WPeChatGPT 尝试对漏洞函数生成EXP
class expCreateHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        funcComment = getFuncComment(ea)
        if "---GPT_VulnPython_START---" in funcComment:
            if ZH_CN:
                print("当前函数已完成 WPeChatGPT:ExpCreater 分析，请查看或清除注释后重试。@Sebao")
            else:
                print("The current function has already been analyzed by WPeChatGPT:ExpCreater. Please check or remove the comment to re-analyze. @Sebao")
            return 0
        decompiler_output = ida_hexrays.decompile(ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if ZH_CN:
            query_text = (
                "你是网络安全专业教师，精通各种语言及不同架构的汇编和漏洞，利用下面函数中的存在的安全隐患或者漏洞，使用 Python 构造POC脚本来，使学生们更好的理解漏洞原理。（回答前加'---GPT_VulnPython_START---'，结尾加'---GPT_VulnPython_END---'）\n"
                f"{decompiler_output}"
            )
        else:
            query_text = (
                "Use Python to construct code to exploit the vulnerability in the following function. "
                "(Prepend '---GPT_VulnPython_START---' and append '---GPT_VulnPython_END---')\n"
                f"{decompiler_output}"
            )
        query_model_async(
            query_text,
            functools.partial(comment_callback, address=ea, view=v, cmtFlag=0, printFlag=3),
            0
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def autoChatFunc(funcTree: str, strings: str, callback):
    messages = []
    messages.append({"role": "user", "content": funcTree})
    messages.append({"role": "user", "content": strings})
    if ZH_CN:
        messages.append({"role": "user", "content": "结合该程序的函数调用结构及其包含的字符串，猜测其运行目的及功能。"})
        messages.append({"role": "user", "content": "请详细分析后告知该程序的运行目的及大致功能。"})
    else:
        messages.append({"role": "user", "content": "Combine the program's function call structure and its strings to guess its purpose and function."})
        messages.append({"role": "user", "content": "Please describe the program's purpose and overall function after careful analysis."})
    t = threading.Thread(target=chat_api_worker, args=(messages, "deepseek-chat", callback))
    t.daemon = True
    t.start()

def chat_api_worker(messages, model, callback):
    try:
        response = openai.ChatCompletion.create(messages=messages, model=model)
    except Exception as e:
        err_str = str(e)
        if "maximum context length" in err_str:
            print("分析数据超出 GPT-3.5-API 的最大长度，请期待后续版本 :)@Sebao")
            return 0
        elif "Cannot connect to proxy" in err_str:
            print("代理出现问题，请稍后重试或检查代理。@Sebao")
            return 0
        else:
            print(f"查询遇到异常：{err_str}")
            return 0
    callback(response)

def handle_response(autoGptfolder, response):
    message = response.choices[0].message
    if ZH_CN:
        print(f"GPT 分析完成，结果已输出至文件夹：{autoGptfolder}")
    else:
        print(f"GPT analysis complete. Result output to folder: {autoGptfolder}")
    with open(autoGptfolder + "GPT-Result.txt", "w") as fp:
        fp.write(message.content)
    print("Auto-WPeGPT finished! :)@Sebao\n")

# Auto-WPeGPT 自动化分析
class autoHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        Auto_WPeGPT.main()
        idb_path = idc.get_idb_path()
        idb_name = 'WPe_' + os.path.basename(idb_path)
        autoGptfolder = os.path.join(os.getcwd(), idb_name) + '\\'
        functreeFilepath = autoGptfolder + "funcTree.txt"
        mainFunctreeFilepath = autoGptfolder + "mainFuncTree.txt"
        stringsFilepath = autoGptfolder + "effectiveStrings.txt"
        with open(functreeFilepath, "r") as f:
            functreeData = f.read()
        with open(mainFunctreeFilepath, "r") as f:
            mainFunctreeData = f.read()
        with open(stringsFilepath, "r") as f:
            stringsData = f.read()
        funcNumber = idaapi.get_func_qty()
        print(f"该二进制文件共有 {funcNumber} 个函数。")
        callback_autogpt = functools.partial(handle_response, autoGptfolder)
        if funcNumber < 150:
            autoChatFunc(functreeData, stringsData, callback_autogpt)
        else:
            autoChatFunc(mainFunctreeData, stringsData, callback_autogpt)
        print("Auto-WPeGPT v0.2 正在开始分析...")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# Gepetto query_model 方法
def query_model(query, cb, max_tokens=1024):
    try:
        response = client.chat.completions.create(
            model="deepseek-ai/DeepSeek-R1",
            messages=[
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": query}
            ],
            temperature=0.7,
            stream=False
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].message.content), ida_kernwin.MFF_WRITE)
    # except openai.InvalidRequestError as e:
    #     m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your prompt;', str(e))
    #     if not m:
    #         print(f"deepseek-chat 无法完成请求：{str(e)}")
    #         return
    #     hard_limit, prompt_tokens = int(m.group(1)), int(m.group(2))
    #     max_tokens = hard_limit - prompt_tokens
    #     if max_tokens >= 750:
    #         print(f"WPeChatGPT-Warning: 上下文长度过长！尝试减少至 {max_tokens} tokens...")
    #         print("正在重新发送请求...")
    #         query_model(query, cb, max_tokens)
    #     else:
    #         print("函数过大，无法使用 ChatGPT-deepseek-chat API 分析。@Sebao")
    except openai.OpenAIError as e:
        err_str = str(e)
        if "That model is currently overloaded" in err_str or "Request timed out" in err_str:
            print("ChatGPT-deepseek-chat API 忙，请稍后重试或检查代理。@Sebao")
        elif "Cannot connect to proxy" in err_str:
            print("代理出现问题，请稍后重试或检查代理。@Sebao")
        else:
            print(f"OpenAI 服务器无法完成请求：{err_str}")
    except Exception as e:
        print(f"查询过程中遇到异常：{str(e)}")

# Gepetto query_model_async 方法
def query_model_async(query, cb, time):
    if time == 0:
        if ZH_CN:
            print("正在发送 ChatGPT-deepseek-chat API 请求，请稍候...@Sebao")
        else:
            print("Sending ChatGPT-deepseek-chat API request, please wait... @Sebao")
        print("请求已发送...")
    else:
        if ZH_CN:
            print("正在重新发送 ChatGPT-deepseek-chat API 请求。@Sebao")
        else:
            print("Resending ChatGPT-deepseek-chat API request. @Sebao")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.daemon = True
    t.start()

# Gepetto comment_callback 方法
def comment_callback(address, view, response, cmtFlag, printFlag):
    if cmtFlag == 0:
        idc.set_func_cmt(address, response, 0)
    elif cmtFlag == 1:
        idc.set_cmt(address, response, 1)
    if view:
        view.refresh_view(False)
    print("deepseek-chat 查询完成！")
    if printFlag == 0:
        if ZH_CN:
            print(f"WPeChatGPT:Explain 分析完成，已为函数 {idc.get_func_name(address)} 添加注释。@Sebao")
        else:
            print(f"WPeChatGPT:Explain finished analyzing, function {idc.get_func_name(address)} commented. @Sebao")
    elif printFlag == 1:
        if ZH_CN:
            print(f"WPeChatGPT:Python 分析完成，已在地址 {hex(address)} 处添加注释。@Sebao")
        else:
            print(f"WPeChatGPT:Python finished parsing, commented at {hex(address)}. @Sebao")
    elif printFlag == 2:
        if ZH_CN:
            print(f"WPeChatGPT:VulnFinder 分析完成，已为函数 {idc.get_func_name(address)} 添加注释。@Sebao")
        else:
            print(f"WPeChatGPT:VulnFinder finished analyzing, function {idc.get_func_name(address)} annotated. @Sebao")
    elif printFlag == 3:
        if ZH_CN:
            print(f"WPeChatGPT:ExpCreater 分析完成，已为函数 {idc.get_func_name(address)} 添加注释。@Sebao")
        else:
            print(f"WPeChatGPT:ExpCreater finished analyzing, commented on function {idc.get_func_name(address)}. @Sebao")

# Gepetto rename_callback 方法
def rename_callback(address, view, response, retries=0):
    m = JSON_REGEX.search(response)
    if not m:
        if retries >= 3:
            print("ChatGPT-deepseek-chat API 无有效响应，请稍后重试。@Sebao")
            return
        print("未提取到有效 JSON，请求模型修正响应...")
        query_model_async(
            "The JSON document provided in this response is invalid. Can you fix it?\n" + response,
            functools.partial(rename_callback, address=address, view=view, retries=retries + 1),
            1
        )
        return
    try:
        names = json.loads(m.group(0))
    except json.decoder.JSONDecodeError:
        if retries >= 3:
            print("响应中的 JSON 无效，请稍后重试。@Sebao")
            return
        print("提取到的 JSON 无效，请求模型修正...")
        query_model_async(
            "Please fix the following JSON document:\n" + m.group(0),
            functools.partial(rename_callback, address=address, view=view, retries=retries + 1),
            1
        )
        return
    function_addr = idaapi.get_func(address).start_ea
    replaced = []
    for orig_name in names:
        if ida_hexrays.rename_lvar(function_addr, orig_name, names[orig_name]):
            replaced.append(orig_name)
    comment = idc.get_func_cmt(address, 0) or ""
    if comment and replaced:
        for n in replaced:
            comment = re.sub(rf'\b{n}\b', names[n], comment)
        idc.set_func_cmt(address, comment, 0)
    if view:
        view.refresh_view(True)
    print("deepseek-chat 查询完成！")
    if ZH_CN:
        print(f"WPeChatGPT:RenameVariable 分析完成，已重命名 {len(replaced)} 个变量。@Sebao")
    else:
        print(f"WPeChatGPT:RenameVariable Completed, renamed {len(replaced)} variables. @Sebao")

# 获取函数注释（使用 or 简化）
def getFuncComment(address):
    return idc.get_func_cmt(address, 0) or idc.get_func_cmt(address, 1) or ""

# 获取地址注释（使用 or 简化）
def getAddrComment(address):
    return idc.get_cmt(address, 0) or idc.get_cmt(address, 1) or ""

# 添加右键菜单动作
class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.explain_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.rename_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.python_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.vulnFinder_action_name, "WPeChatGPT/")
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.expPython_action_name, "WPeChatGPT/")

class myplugin_WPeChatGPT(idaapi.plugin_t):
    autoWPeGPT_action_name = "WPeChatGPT:Auto-WPeGPT"
    autoWPeGPT_menu_path = "Edit/WPeChatGPT/Auto-WPeGPT/Auto-WPeGPT v0.2"
    explain_action_name = "WPeChatGPT:Explain_Function"
    explain_menu_path = "Edit/WPeChatGPT/函数分析"
    rename_action_name = "WPeChatGPT:Rename_Function"
    rename_menu_path = "Edit/WPeChatGPT/重命名函数变量"
    python_action_name = "WPeChatGPT:Python_Function"
    python_menu_path = "Edit/WPeChatGPT/Python还原此函数"
    vulnFinder_action_name = "WPeChatGPT:VulnFinder_Function"
    vulnFinder_menu_path = "Edit/WPeChatGPT/二进制漏洞查找"
    expPython_action_name = "WPeChatGPT:VulnPython_Function"
    expPython_menu_path = "Edit/WPeChatGPT/尝试生成Exploit"
    wanted_name = 'WPeChatGPT'
    wanted_hotkey = ''
    comment = "WPeChatGPT Plugin for IDA"
    menu = None
    flags = 0

    def init(self):
        # 检查反编译器是否可用
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        if ZH_CN:
            # 创建 Auto-WPeGPT 动作
            autoWPeGPT_action = idaapi.action_desc_t(
                self.autoWPeGPT_action_name,
                '二进制文件自动化分析 v0.2',
                autoHandler(),
                "",
                '使用 deepseek-chat 对二进制文件进行自动化分析',
                199
            )
            idaapi.register_action(autoWPeGPT_action)
            idaapi.attach_action_to_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name, idaapi.SETMENU_APP)
            # 函数分析动作
            explain_action = idaapi.action_desc_t(
                self.explain_action_name,
                '函数分析',
                ExplainHandler(),
                "Ctrl+Alt+G",
                '使用 deepseek-chat 分析当前函数',
                199
            )
            idaapi.register_action(explain_action)
            idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
            # 变量重命名动作
            rename_action = idaapi.action_desc_t(
                self.rename_action_name,
                '重命名函数变量',
                RenameHandler(),
                "Ctrl+Alt+R",
                "使用 deepseek-chat 重命名当前函数的变量",
                199
            )
            idaapi.register_action(rename_action)
            idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
            # Python 还原函数动作
            python_action = idaapi.action_desc_t(
                self.python_action_name,
                'Python还原此函数',
                PythonHandler(),
                "",
                "使用 deepseek-chat 分析当前函数并用python3还原",
                199
            )
            idaapi.register_action(python_action)
            idaapi.attach_action_to_menu(self.python_menu_path, self.python_action_name, idaapi.SETMENU_APP)
            # 漏洞查找动作
            vulnFinder_action = idaapi.action_desc_t(
                self.vulnFinder_action_name,
                '二进制漏洞查找',
                FindVulnHandler(),
                "Ctrl+Alt+E",
                '使用 deepseek-chat 在当前函数中查找漏洞',
                199
            )
            idaapi.register_action(vulnFinder_action)
            idaapi.attach_action_to_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name, idaapi.SETMENU_APP)
            # EXP 生成动作
            expPython_action = idaapi.action_desc_t(
                self.expPython_action_name,
                '尝试生成Exploit',
                expCreateHandler(),
                "",
                '使用 deepseek-chat 尝试对漏洞函数生成EXP',
                199
            )
            idaapi.register_action(expPython_action)
            idaapi.attach_action_to_menu(self.expPython_menu_path, self.expPython_action_name, idaapi.SETMENU_APP)
            self.menu = ContextMenuHooks()
            self.menu.hook()
            print("Auto-WPeGPT v0.2 已就绪。")
            print("WPeChatGPT v2.4 正常运行！ :)@Sebao\n")
        else:
            autoWPeGPT_action = idaapi.action_desc_t(
                self.autoWPeGPT_action_name,
                'Automated analysis v0.2',
                autoHandler(),
                "",
                'Using deepseek-chat for automated binary analysis',
                199
            )
            idaapi.register_action(autoWPeGPT_action)
            idaapi.attach_action_to_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name, idaapi.SETMENU_APP)
            explain_action = idaapi.action_desc_t(
                self.explain_action_name,
                'Function analysis',
                ExplainHandler(),
                "Ctrl+Alt+G",
                'Analyze the current function using deepseek-chat',
                199
            )
            idaapi.register_action(explain_action)
            idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)
            rename_action = idaapi.action_desc_t(
                self.rename_action_name,
                'Rename function variables',
                RenameHandler(),
                "Ctrl+Alt+R",
                "Rename variables of the current function using deepseek-chat",
                199
            )
            idaapi.register_action(rename_action)
            idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)
            python_action = idaapi.action_desc_t(
                self.python_action_name,
                'Python restores this function',
                PythonHandler(),
                "",
                "Analyze and restore the current function with python3 using deepseek-chat",
                199
            )
            idaapi.register_action(python_action)
            idaapi.attach_action_to_menu(self.python_menu_path, self.python_action_name, idaapi.SETMENU_APP)
            vulnFinder_action = idaapi.action_desc_t(
                self.vulnFinder_action_name,
                'Vulnerability finding',
                FindVulnHandler(),
                "Ctrl+Alt+E",
                'Find vulnerabilities in the current function using deepseek-chat',
                199
            )
            idaapi.register_action(vulnFinder_action)
            idaapi.attach_action_to_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name, idaapi.SETMENU_APP)
            expPython_action = idaapi.action_desc_t(
                self.expPython_action_name,
                'Try to generate Exploit',
                expCreateHandler(),
                "",
                'Use deepseek-chat to generate an exploit for the vulnerability',
                199
            )
            idaapi.register_action(expPython_action)
            idaapi.attach_action_to_menu(self.expPython_menu_path, self.expPython_action_name, idaapi.SETMENU_APP)
            self.menu = ContextMenuHooks()
            self.menu.hook()
            print("Auto-WPeGPT v0.2 is ready.")
            print("WPeChatGPT v2.4 works fine! :)@Sebao\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.autoWPeGPT_menu_path, self.autoWPeGPT_action_name)
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.python_menu_path, self.python_action_name)
        idaapi.detach_action_from_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name)
        idaapi.detach_action_from_menu(self.expPython_menu_path, self.expPython_action_name)
        if self.menu:
            self.menu.unhook()
        return

def PLUGIN_ENTRY():
    if openai.api_key == "ENTER_OPEN_API_KEY_HERE":
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            print("未找到 API_KEY，请在脚本中填写 openai.api_key! :(@Sebao")
            raise ValueError("No valid OpenAI API key found")
    return myplugin_WPeChatGPT()