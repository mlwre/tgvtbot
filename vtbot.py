#!/bin/env python2
# encoding: utf-8
# -*- coding: utf-8 -*-

import telegram, os, subprocess, threading, sqlite3, json, argparse, hashlib, re, sys, signal, requests

vtapi = 'VT API'  # VirusTotal API key
tgtoken = 'TG BOT API'   # Telegram API key
vtbase = 'https://www.virustotal.com/vtapi/v2/'
bot = None


def sendreply(fn):

    """
    Take a string returned from decorated function
    and send into a corresponding chat
    """

    def wrapper(*pargs, **kwargs):
        update = pargs[1]
        reply = fn(*pargs, **kwargs)
        print('------------------------')
        if reply:
            if len(reply) < 4096:
                bot.sendMessage(chat_id=update.message.chat_id, text=reply)
            else:
                for i in xrange(0, len(reply), 4096):
                    bot.sendMessage(chat_id=update.message.chat_id, text=reply[i:i+4096])
    return wrapper


def parseFileURLReport(fn):

    """
    This decorator gets a json object from the VT api and
    transform it into readable state.

    Especially for getFileReport and getURLReport

    """
    def wrapper(*pargs, **kwargs):
        it = fn(*pargs, **kwargs)
        print(it)

        if not it:
            return False

        if type(it) == str:
            return it   # If http error, return it
        else:
            if it['response_code'] == -2:
                if it['verbose_msg'] == 'Your resource is queued for analysis':
                    return "%s\n\nScan id: %s\n\nWait and get report then." % (it['verbose_msg'], it['scan_id'])
            elif it['response_code'] == 0:  # Send error message
                return it['verbose_msg']

        print('value')
        sn = ''

        try:
            md5 = it['md5']     # if scanning file
        except KeyError:
            sn += "\nResults for: %s\n\nRate:%s/%s" % (it['resource'], it['positives'], it['total'])
        else:
            sn += "\nResults for: %s \n\nRate:%s/%s" % (it['md5'], it['positives'], it['total'])

        if int(it['positives']) > 0:
            sn += "\n\nDetected by:\n"
            detected = ''
            for i in it['scans']:
                if it['scans'][i]['detected'] == True:
                    detected += "%s: %s\n" % (i, it['scans'][i]['result'])
            sn += detected
        else:
            sn += "\nClear!"

        sn += "\n\nResult URL: %s" % it['permalink']
        print(kwargs)
        print('---------------------')
        return sn
    return wrapper


def parseIpAddressReport(fn):
    """
    This decorator gets a json object from the VT api and
    transform it into readable state.

    Especially for getIpAddressReport

    """

    def wrapper(*pargs, **kwargs):
        it = fn(*pargs, **kwargs)
        print(it)
        resp = ''
        if it['response_code'] == 1:
            resp += '%s\n\n' % it['verbose_msg']
            resp += 'Country: %s\n' % it['country']
            resp += 'Owner: %s\n' % it['as_owner']
            resp += '\nResolutions:\n'
            
            for reso in it['resolutions']:
                print(reso)
                resp += '%s\nLast resolved: %s\n\n' % (reso['hostname'], reso['last_resolved'])
            
            resp += '\nDetected URLs:\n'

            for url in it['detected_urls']:
                resp += '%s/%s %s %s' % (url['positives'], url['total'], url['scan_date'], url['url'])
        elif it['response_code'] == 0:
            return it['verbose_msg']
        return resp
    return wrapper


def parseDomainReport(fn):
    """
    This decorator gets a json object from the VT api and
    transform it into readable state.

    Especially for getDomainReport

    """

    def wrapper(*pargs, **kwargs):
        it = fn(*pargs, **kwargs)
        print(it)
        resp = ''
        if it['response_code'] == 1:
            resp += '%s\n\n' % it['verbose_msg']
            
            if 'Opera domain info' in it:
                resp += 'Opera domain info: %s\n\n' % it['Opera domain info']

            if 'BitDefender domain info' in it:
                resp += 'BitDefender domain info: %s\n\n' % it['BitDefender domain info']

            if 'Alexa domain info' in it:
                resp += 'Alexa domain info: %s\n\n' % it['Alexa domain info']

            if 'Webutation domain info' in it:
                resp += 'Webutation domain info: %s\nAdult content: %s\nSafety score: %s\n\n' % (it['Webutation domain info']['Verdict'], it['Webutation domain info']['Adult content'], it['Webutation domain info']['Safety score'])

            if 'BitDefender category' in it:
                resp += 'BitDefender category: %s\n\n' % it['BitDefender category']

            if 'Alexa category' in it:
                resp += 'Alexa category: %s\n\n' % it['Alexa category']
                
            if 'Websense ThreatSeeker category' in it:
                resp += 'Websense ThreatSeeker category: %s\n\n' % it['Websense ThreatSeeker category']

            if 'TrendMicro category' in it:
                resp += 'TrendMicro category: %s\n\n' % it['TrendMicro category']

            if 'Dr.Web category' in it:
                resp += 'Dr.Web category: %s\n\n' % it['Dr.Web category']

            if 'categories' in it:
                resp += 'Categories:\n'
                for cat in it['categories']:
                    resp += '%s\n' % cat

            if 'whois' in it:
                resp += '\nWhois: \n%s\n\n' % it['whois']

            if 'resolutions' in it:
                resp += '\nResolutions:\n'

                for reso in it['resolutions']:
                   resp += '%s\nLast resolved: %s\n\n' % (reso['ip_address'], reso['last_resolved'])

            if 'detected_downloaded_samples' in it:
                resp += 'Detected downloaded samples:\n'
                for dsamples in it['detected_downloaded_samples']:
                    resp += '%s\n%s/%s\nsha256: %s\n\n' % (dsamples['date'], dsamples['positives'], dsamples['total'], dsamples['sha256'])
            
            if 'undetected_downloaded_samples' in it:
                resp += 'Undetected downloaded samples:\n'
                for udsamples in it['undetected_downloaded_samples']:
                    resp += '%s\n%s/%s\nsha256: %s\n\n' % (udsamples['date'], udsamples['positives'], udsamples['total'], udsamples['sha256'])

            if 'undetected_referrer_samples' in it:
                resp += 'Undetected referrer samples:\n'
                for udrsamples in it['undetected_referrer_samples']:
                    resp += '%s/%s\nsha256: %s\n\n' % (udrsamples['positives'], udrsamples['total'], udrsamples['sha256'])

            if 'detected_communicating_samples' in it:
                resp += 'Detected communicating samples:\n'
                for dcsamples in it['detected_downloaded_samples']:
                    resp += '%s\n%s/%s\nsha256: %s\n\n' % (dcsamples['date'], dcsamples['positives'], dcsamples['total'], dcsamples['sha256'])

            if 'subdomains' in it:
                resp += '\nSubdomains:\n'
                for subd in it['subdomains']:
                   resp += '%s\n' % subd

            if 'detected_urls' in it:

                resp += '\nDetected URLs:\n'

                for url in it['detected_urls']:
                   resp += '%s/%s %s %s\n' % (url['positives'], url['total'], url['scan_date'], url['url'])

        
        if len(resp) < 4096: # if reply size more than message limit, send as file
            return resp
        else:
            print('sending file')
            with open('domain_report.txt', 'w') as drfile:
                drfile.write(resp)
            bot.sendDocument(chat_id=pargs[1].message.chat_id, document=open('domain_report.txt', 'rb'), filename='domain_report.txt')
            print('file sent')
            return '%s\n\nOutput is too long. Take the file.' % it['verbose_msg']
        


    return wrapper


def messageChecker(bot, update):

    """
    Check messages on attached files
    """

    print(update)
    if update.message.document:
        scanFile(bot, update)


@sendreply
def scanFile(bot, update, **kwargs):

    """
    Send files to scan
    """

    url = vtbase + "file/scan"
    param = {"apikey": vtapi}
    jsonrecvfile = bot.getFile(update.message.document.file_id)
    print(jsonrecvfile)
    recvfile = requests.get(jsonrecvfile.file_path)
    files = {"file": recvfile.content}
    res = requests.post(url, data=param, files=files)
    if res.status_code == 200:  # HTTP OK
        resmap = json.loads(res.text)
        scan_id = resmap['scan_id']
        scan_id = scan_id.split('-')
        print(scan_id)
        return "%s\n\nhttp://virustotal.com/file/%s/analysis/%s" % (resmap['verbose_msg'], scan_id[0], scan_id[1])


@sendreply
def rescan(bot, update, **kwargs):

    """
    Rescan a file
    """

    print(update)

    text = update.message.text
    md5 = text.split(' ')

    try:
        md5 = md5[1]
    except IndexError:
        return "Specify an argument"

    param = {'resource':md5,'apikey':vtapi, "allinfo":1}
    url = vtbase + "file/rescan"
    try:
        result = requests.get(url, params=param).text
    except Exception as e:
        return str(e)

    result = json.loads(res)
    print(result)
    return "\n\tVirus Total Rescan Initiated for %s\n\n%s" % (md5, result['permalink'])


@sendreply
def URLScan(bot, update, **kwargs):

    """
    Scan URL    -- not working on VirusTotal side
    """


    text = update.message.text
    scanurl = text.split(' ')

    print('scanurl: ' + str(scanurl))
    try:
        scanurl = scanurl[1]
    except IndexError:
        return "Specify an argument"
    attr = {"apikey": vtapi, "url": scanurl}
    url = vtbase + "url/scan"
    try:
        result = requests.get(url, params=param).text
    except Exception as e:
        return str(e)

    print(result)

    try:
        it = json.loads(result)
    except ValueError:
        return result
    else:
        return 'Scanning %s\n%s\n\nUrl:%s' % (it['url'], it['verbose_msg'], it['permalink'])


@sendreply
@parseFileURLReport
def getFileReport(bot, update, md5=None, **kwargs):

    """
    Get file report

    """

    print(md5)
    if md5 == None:
        text = update.message.text
        md5 = text.split(' ')
        try:
            md5 = md5[1]
        except IndexError:
            return "Specify an argument"
    
    param = {'resource': md5,'apikey': vtapi,'allinfo': '1'}
    url = vtbase + "file/report?"
    try:
        result = requests.get(url, params=param).text
    except Exception as e:
        return str(e)
    try:
        jdata = json.loads(result)
    except Exception:
        return 'Something went wrong'
    resp = jdata
    print('-----------------------------')
    return resp      


@sendreply
@parseFileURLReport
def getURLReport(bot, update, urltoscan=None, **kwargs):

    """
    Get URL report

    """

    print(urltoscan)
    if urltoscan == None:
        text = update.message.text
        urltoscan = text.split(' ')
        try:
            urltoscan = urltoscan[1]
        except IndexError:
            return "Specify an argument"
    
    param = {'resource': urltoscan,'apikey': vtapi,'allinfo': '1'}
    url = vtbase + "url/report?"
    try:
        result = requests.get(url, params=param).text
    except Exception as e:

        return str(e)
    try:
        jdata = json.loads(result)
    except Exception:
        return 'Something went wrong'
    resp = jdata
    print('-----------------------------')
    return resp


@sendreply
@parseIpAddressReport
def getIpAddressReport(bot, update, iptoscan=None, **kwargs):

    """
    Get ip address report

    """


    if iptoscan == None:
        text = update.message.text
        iptoscan = text.split(' ')
        try:
            iptoscan = iptoscan[1]
        except IndexError:
            return "Specify an argument"
    
    param = {'ip': iptoscan,'apikey': vtapi,'allinfo': '1'}
    url = vtbase + "ip-address/report?"
    try:
        result = requests.get(url, params=param)
    except Exception as e:
        return str(e)
    try:
        jdata = json.loads(result.text)
    except Exception:
        print(result.text)
        return 'Something went wrong'
    resp = jdata
    print('-----------------------------')
    return resp

@sendreply
@parseDomainReport
def getDomainReport(bot, update, urltoscan=None, **kwargs):

    """
    Get domain report

    """
    print("DomainReport")
    if urltoscan == None:
        text = update.message.text
        urltoscan = text.split(' ')
        try:
            urltoscan = urltoscan[1]
        except IndexError:
            return "Specify an argument"
    print(urltoscan)
    param = {'domain': urltoscan,'apikey': vtapi,'allinfo': '1'}
    url = vtbase + "domain/report"

    try:
        result = requests.get(url, params=param).text
    except Exception as e:
        return str(e)
    try:
        jdata = json.loads(result)
    except Exception:
        print(result)
        return 'Something went wrong'
    print(jdata)
    print('-----------------------------')
    return jdata


@sendreply
def start(bot, update, **kwargs):

    """
    The first command
    """

    text = '''
    Hello! This bot checks your MD5 hash in VirusTotal database and send result to you.
    '''
    return text


@sendreply
def help(bot, update, **kwargs):

    """
    Show help page
    """

    text = '''
    Help page:
    /help - This page
    /get_file_report - Get file report using md5
    /get_url_report - Get URL report using md5 or url
    /get_ip_report - Get IP address report
    /get_domain_report - Get a domain report
    /scan_url - Check an URL on malware
    /rescan - Rescan a file

    send a file to scan it

    also i can make a coffee
    '''
    return text


@sendreply
def make_a_coffee(bot, update, **kwargs):

    """
    An Eatser egg
    """

    text = '☕'
    print('Your coffee')
    return text


def main():
    global bot
    global tgtoken
    bot = telegram.Bot(token=tgtoken)
    updater = telegram.Updater(token=tgtoken)
    dispatcher = updater.dispatcher
    updater.start_polling()
    dispatcher.addTelegramCommandHandler('start', start)
    dispatcher.addTelegramCommandHandler('help', help)
    dispatcher.addTelegramCommandHandler('make_a_coffee', make_a_coffee)
    dispatcher.addTelegramCommandHandler('get_file_report', getFileReport)
    dispatcher.addTelegramCommandHandler('get_url_report', getURLReport)
    dispatcher.addTelegramCommandHandler('get_ip_report', getIpAddressReport)
    dispatcher.addTelegramCommandHandler('get_domain_report', getDomainReport)
    dispatcher.addTelegramCommandHandler('scan_url', URLScan)
    dispatcher.addTelegramCommandHandler('rescan', rescan)
    dispatcher.addTelegramMessageHandler(messageChecker)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
