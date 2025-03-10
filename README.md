# WPeChatGPT
项目来自WPeChatGPT,修改了一些代码优化提示词，修改了API接口以适配硅基流动的deepseek r1 API接口

@sebao
@KDEV

# WPeChatGPT

基于与 ChatGPT 相同模型的IDA 插件，使用 OpenAI 发布的 gpt-3.5-turbo 模型，可以有助于分析师们快速分析二进制文件。

当前 WPeChatGPT 支持的功能包括：

分析函数的使用环境、预期目的、函数功能。

重命名函数的变量。

尝试用 python3 对函数进行还原，此功能主要是针对较小块的函数（如一个异或解密函数）。

在当前函数中查找是否存在漏洞。

尝试用 python 对漏洞函数生成对应的 EXP。

利用 GPT 全自动分析二进制文件，具体参考节 Auto-WPeGPT。

ChatGPT 的分析结果仅供参考，不然我们这些分析师就当场失业了。XD

# Usage : 

用IDA里面的python.exe -m pip install -r requirement.txt

然后将两个py文件放到  \IDA安装目录\pluginsplugins文件夹内

在WPeChatGPT.py里面填写硅基流动的api
