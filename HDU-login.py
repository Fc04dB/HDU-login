import hashlib
import hmac
import math
import time
import requests
import re

timestamp = int(time.time())

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
}

class HDU_Login:
    def __init__(self,
                 url_login_page="https://portal.hdu.edu.cn/srun_portal_pc?ac_id=1&theme=pro",
                 url_get_challenge_api="https://portal.hdu.edu.cn/cgi-bin/get_challenge",
                 url_login_api="https://portal.hdu.edu.cn/cgi-bin/srun_portal",
                 n="200",
                 vtype="1",
                 acid="1",
                 enc="srun_bx1"):
        # urls
        self.url_login_page = url_login_page
        self.url_get_challenge_api = url_get_challenge_api
        self.url_login_api = url_login_api

        # 静态参数
        self.n = n
        self.vtype = vtype
        self.ac_id = acid
        self.enc = enc

    def login(self):
        self.username = input("请输入账号：")
        self.password = input("请输入密码：")

        self.get_ip()
        self.get_token()
        self.get_login_response()

    def get_ip(self):
        self._page_response = requests.get(self.url_login_page, headers=header)
        self.ip = re.search('ip     : "(.*?)"', self._page_response.text).group(1)
        print(f"获取ip成功，ip：{self.ip}")

    def get_token(self):
        params_get_challenge = {
            'callback': "jQuery1124044183695508093734_" + str(timestamp),
            'username': self.username,
            'ip': self.ip,
            '_': int(time.time())
        }

        self._challenge_response = requests.get(
            self.url_get_challenge_api, params=params_get_challenge, headers=header)

        self.token = re.search('"challenge":"(.*?)"',
                               self._challenge_response.text).group(1)
        print(f"获取challege成功，challege：{self.token}")

    def get_login_response(self):

        #### 加密处理函数
        # 模拟md5加密
        def get_md5(password, token):
            return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

        # 模拟sha1加密
        def get_sha1(value):
            return hashlib.sha1(value.encode()).hexdigest()

        # base64_encode

        def get_base64(s):
            def _getbyte(s, i):
                x = ord(s[i])
                if (x > 255):
                    print("INVALID_CHARACTER_ERR: DOM Exception 5")
                    exit(0)
                return x

            _PADCHAR = "="
            _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
            i = 0
            b10 = 0
            x = []
            imax = len(s) - len(s) % 3
            if len(s) == 0:
                return s
            for i in range(0, imax, 3):
                b10 = (_getbyte(s, i) << 16) | (
                        _getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
                x.append(_ALPHA[(b10 >> 18)])
                x.append(_ALPHA[((b10 >> 12) & 63)])
                x.append(_ALPHA[((b10 >> 6) & 63)])
                x.append(_ALPHA[(b10 & 63)])
            i = imax
            if len(s) - imax == 1:
                b10 = _getbyte(s, i) << 16
                x.append(_ALPHA[(b10 >> 18)] +
                         _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR)
            elif len(s) - imax == 2:
                b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8)
                x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)
                ] + _ALPHA[((b10 >> 6) & 63)] + _PADCHAR)
            else:
                # do nothing
                pass
            return "".join(x)

        # xencode

        def force(msg):
            ret = []
            for w in msg:
                ret.append(ord(w))
            return bytes(ret)

        def get_xencode(msg, key):

            def lencode(msg, key):
                l = len(msg)
                ll = (l - 1) << 2
                if key:
                    m = msg[l - 1]
                    if m < ll - 3 or m > ll:
                        return
                    ll = m
                for i in range(0, l):
                    msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
                        msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
                if key:
                    return "".join(msg)[0:ll]
                return "".join(msg)

            def sencode(msg, key):

                def ordat(msg, idx):
                    if len(msg) > idx:
                        return ord(msg[idx])
                    return 0

                l = len(msg)
                pwd = []
                for i in range(0, l, 4):
                    pwd.append(
                        ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
                        | ordat(msg, i + 3) << 24)
                if key:
                    pwd.append(l)
                return pwd

            if msg == "":
                return ""
            pwd = sencode(msg, True)
            pwdk = sencode(key, False)
            if len(pwdk) < 4:
                pwdk = pwdk + [0] * (4 - len(pwdk))
            n = len(pwd) - 1
            z = pwd[n]
            y = pwd[0]
            c = 0x86014019 | 0x183639A0
            m = 0
            e = 0
            p = 0
            q = math.floor(6 + 52 / (n + 1))
            d = 0
            while 0 < q:
                d = d + c & (0x8CE0D9BF | 0x731F2640)
                e = d >> 2 & 3
                p = 0
                while p < n:
                    y = pwd[p + 1]
                    m = z >> 5 ^ y << 2
                    m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                    m = m + (pwdk[(p & 3) ^ e] ^ z)
                    pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
                    z = pwd[p]
                    p = p + 1
                y = pwd[0]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (pwdk[(p & 3) ^ e] ^ z)
                pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
                z = pwd[n]
                q = q - 1
            return lencode(pwd, False)

        info_params = {
            'username': self.username,
            'password': self.password,
            'ip': self.ip,
            'acid': self.ac_id,
            'enc_ver': self.enc
        }
        info = re.sub("'", '"', str(info_params))
        self.info = re.sub(" ", '', info)

        self.encrypted_info = "{SRBX1}" + get_base64(get_xencode(self.info, self.token))

        self.md5 = get_md5("", self.token)
        self.encrypted_md5 = "{MD5}" + self.md5

        self.chkstr = self.token + self.username
        self.chkstr += self.token + self.md5
        self.chkstr += self.token + self.ac_id
        self.chkstr += self.token + self.ip
        self.chkstr += self.token + self.n
        self.chkstr += self.token + self.vtype
        self.chkstr += self.token + self.encrypted_info

        self.encrypted_chkstr = get_sha1(self.chkstr)

        login_info_params = {
            'callback': "jQuery1124044183695508093734_" + str(timestamp),
            'action': "login",
            'username': self.username,
            'password': self.encrypted_md5,
            'os': "Linux",
            'name': "Linux",
            'double_stack': 0,
            'chksum': self.encrypted_chkstr,
            'info': self.encrypted_info,
            'ac_id': self.ac_id,
            'ip': self.ip,
            'n': self.n,
            'type': self.vtype,
            '_': int(time.time())
        }
        self._login_response = requests.get(
            self.url_login_api, params=login_info_params, headers=header)

        self._login_result = re.search(
            '"suc_msg":"(.*?)"', self._login_response.text).group(1)

        if re.search("successful", self._login_response.text):
            print("登陆成功!!!!!!!")

if __name__ == '__main__':
    hdu = HDU_Login()
    hdu.login()