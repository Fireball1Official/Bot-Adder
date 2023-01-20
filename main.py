import httpx,os
os.system("pip install tls_client")
import tls_client
import json
import base64
import requests
import time
__useragent__ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"#requests.get('https://discord-user-api.cf/api/v1/properties/web').json()['chrome_user_agent']
build_number = 165485#int(requests.get('https://discord-user-api.cf/api/v1/properties/web').json()['client_build_number'])
cv = "108.0.0.0"
__properties__ = base64.b64encode(json.dumps({"os": "Windows","browser": "Chrome","device": "PC","system_locale": "en-GB","browser_user_agent": __useragent__,"browser_version": cv,"os_version": "7","referrer": "","referring_domain": "","referrer_current": "","referring_domain_current": "","release_channel": "stable","client_build_number": build_number,"client_event_source": None}, separators=(',', ':')).encode()).decode()

def get_headers(token, url):
  headers = {
    "Authorization": token,
    "Origin": "https://discord.com",
    "Accept": "*/*",
    "X-Discord-Locale": "en-GB",
    "X-Super-Properties": __properties__,
    "User-Agent": __useragent__,
    "Referer": url,
    "X-Debug-Options": "bugReporterEnabled",
    "Content-Type": "application/json"
  }
  return headers

def authorize(urlauth,url,token,captcha,guild):
  data = {"authorize": True, "permissions": 0, "guild_id": guild, "captcha_service": "hcaptcha", "captcha_key": captcha}
  client = tls_client.Session(client_identifier="firefox_102")
  client.headers.update(get_headers(token,url))
  r1 = client.get(url)
  r2 = client.get(urlauth)
  r3 = client.post(urlauth, json=data)
  print(r3.text)

def check_ifnotin(id,sv):
  r = requests.get(f"https://discord.com/api/v9/guilds/{sv}/members/{id}", headers={"Authorization": token})
  try:
    ok = r.json()
  except:
    print("Rate Limited")
    os.system("kill 1")
  try:
    ok["avatar"]
  except:
    return True
  return False




def get_captcha():
  print("Getting Captcha Key......")
  capres = requests.get("https://Capsolverv2.notauth1337.repl.co/solve", json={"sitekey": "f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34", "site": "https://discord.com/api/oauth2/authorize", "key": "1"}, headers={"Authorization": "HelloImUnderTheWater!"})
  #print(capres.text)
  capkey = capres.json()["key"]
  print("Got Captcha Key")
  return capkey

bot_ids = [1059446291979051078,1059445664020439040,1059444980525060106,10594445610820689921059443358394765343]
server_ids = [1050036720298639410,1049600923195949107,1049588580449792050,1036139370278830151,1022508180644843620,1034016091464269834,1034509828644687912,1010840955332603914,1008362353705881671,964357497827774465,898234397675909170,1025457548045844510,1032274764326240346,973833197609680896,1012336343654867009]
token = "enter token"
delay = 5


def generate_url(id, auth):
  if auth:
    url = f"https://discord.com/api/v10/oauth2/authorize?client_id={id}&permissions=0&scope=bot"
  else:
    url = f"https://discord.com/oauth2/authorize?client_id={id}&permissions=0&scope=bot"
  return url


def main():
  print("Bot Adder By Auth#1337")
  for server in server_ids:
    for bot in bot_ids:
      url1 = generate_url(bot, False)
      url2 = generate_url(bot,True)
      print(f"Authorizing Bot {bot} To Server {server}")
      if check_ifnotin(bot,server):
        captcha = get_captcha()
        #captcha=None
        authorize(url2,url1,token,captcha,server)
        print(f"Authorized Bot {bot} To Server {server}")
        print(f"Sleeping {delay} Seconds")
        time.sleep(delay)
      else:
        print("already bot in sv")


if __name__ == "__main__":
  main()
