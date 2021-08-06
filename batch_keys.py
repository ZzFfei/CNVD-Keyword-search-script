import requests
import re
from requests.utils import add_dict_to_cookiejar
import execjs
import hashlib
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def title():   #定义使用介绍方法
    print('+---------------------------------+')
    print('+ \033[032m爬虫: CNVD关键字搜索漏洞    \033[0m')
    print('+ \033[034m使用格式: python3 batch_keys.py    \033[0m')
    print('+ \033[032mAuthor: FF    \033[0m')
    print('+---------------------------------+')

def get__jsl_clearance_s(data):
    """
    通过加密对比得到正确cookie参数
    :param data: 参数
    :return: 返回正确cookie参数
    """
    chars = len(data['chars'])
    for i in range(chars):
        for j in range(chars):
            __jsl_clearance_s = data['bts'][0] + data['chars'][i] + data['chars'][j] + data['bts'][1]
            encrypt = None
            if data['ha'] == 'md5':
                encrypt = hashlib.md5()
            elif data['ha'] == 'sha1':
                encrypt = hashlib.sha1()
            elif data['ha'] == 'sha256':
                encrypt = hashlib.sha256()
            encrypt.update(__jsl_clearance_s.encode())
            result = encrypt.hexdigest()
            if result == data['ct']:
                return __jsl_clearance_s

# global session
def setCookie(url):
    global session
    session = requests.session()

    response1 = session.get(url)
    jsl_clearance_s = re.findall(r'cookie=(.*?);location', response1.text)[0]
    jsl_clearance_s = str(execjs.eval(jsl_clearance_s)).split('=')[1].split(';')[0]
    add_dict_to_cookiejar(session.cookies, {'__jsl_clearance_s': jsl_clearance_s})

    response2 = session.get(url)
    data = json.loads(re.findall(r';go\((.*?)\)', response2.text)[0])
    jsl_clearance_s = get__jsl_clearance_s(data)
    add_dict_to_cookiejar(session.cookies, {'__jsl_clearance_s': jsl_clearance_s})
    return session.cookies

def cnvd(keyword, num):
    url = "https://www.cnvd.org.cn/flaw/list.htm?flag=true&keyword=" + keyword + "&max=" + num
    response = session.post(url=url)
    print(response.status_code)
    rules = r'<td width="45%"><img.*?src="/images/wrang_con.gif"></img> <a.*?href="/flaw/show/(.*?)".*?title="(.*?)">'
    bingo = re.compile(rules, re.DOTALL).findall(response.text)
    for i in bingo:
        print(i)


if __name__ == '__main__':
    title()
    t = setCookie('https://www.cnvd.org.cn/')
    keyword = input("请输入CNVD查询关键字：")
    num = input("请输入需要查询的条目：")
    cnvd(keyword, num)
    print('+ \033[032ma查询完毕！    \033[0m')