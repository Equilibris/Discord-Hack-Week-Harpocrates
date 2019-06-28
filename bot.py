import discord
from discord.ext import commands
import os
import subprocess
import webbrowser


import base64
import random

import asyncio
import json
from configparser import ConfigParser

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# split here

commandPrefix = '.'

client = commands.Bot(command_prefix = f'{commandPrefix}')
client.remove_command('help')

botAdmins = ['Equilibris#2431', 'Tankie#8595']

parser = ConfigParser()
parser.read('cfg.ini')

token = parser.get('setings', 'token')
logServerId = parser.get('setings', 'logserver')
FBServerId = parser.get('setings', 'FBServer')

logServerId = int(logServerId)
FBServerId = int(FBServerId)

async def tactical_pause(num = 0):

    await asyncio.sleep(5)

    if num == 0:

        await client.change_presence(activity=discord.Game(name=f'with ones and zeros'))

        num = 1

    elif num == 1:


        await client.change_presence(activity=discord.Game(name=f'send {commandPrefix}help for help'))

        num = 2

    elif num == 2:


        await client.change_presence(activity=discord.Game(name=f'my ping is {round(client.latency *1000)}ms'))

        num = 0


    await tactical_pause(num)


# split here

datalimit = 3

chrsets = {

    'ascii' : r'!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~',
    'english' : 'abcdefghijklmnopqrstuvwxyz',
    'english(caps)' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'english+caps' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'english+nums' : '0123456789abcdefghijklmnopqrstuvwxyz',
    'english+caps+nums' : '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'norwegian' : 'abcdefghijklmnopqrstuvwxyzæøå',
    'norwegian(caps)' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ',
    'norwegian+caps' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅabcdefghijklmnopqrstuvwxyzæøå',
    'norwegian+nums' : '0123456789abcdefghijklmnopqrstuvwxyzæøå',
    'norwegian+nums+caps' : '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅabcdefghijklmnopqrstuvwxyzæøå'

}

modesForE=[

    'e',
    'E',
    'Encrypt',
    'encrypt',
    'Enc',
    'enc'
]

modesForD=[

    'd',
    'D',
    'Decrypt',
    'decrypt',
    'Dec',
    'dec'

]

# hash methods start # hash methods start # hash methods start # hash methods start # hash methods start # hash methods start # hash methods start

hashLen = 32

hashIter = 100000

salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',

# start hashes # start hashes # start hashes # start hashes # start hashes # start hashes # start hashes

allHashes=[

    'MD5',

    'SHA512',
    'SHA384',
    'SHA256',
    'SHA224',

    'SHA3_224',
    'SHA3_256',
    'SHA3_384',
    'SHA3_512',

    'SHA512_224',
    'SHA512_256',

    'SHAKE128',
    'SHAKE256'

]


try:
    async def MD5(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.MD5(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA512(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA512(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA384(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA384(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA256(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA224(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA224(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA3_224(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA3_224(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA3_256(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA3_256(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA3_384(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA3_384(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA3_512(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA3_512(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA512_224(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA512_224(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHA512_256(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA512_256(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHAKE128(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHAKE128(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)


    async def SHAKE256(message):

        message = message.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHAKE256(),
            length = hashLen,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = hashIter,
            backend = default_backend()
        )


        output = base64.urlsafe_b64encode(kdf.derive(message))

        return(output)
except Exception as e:
    raise e

# end hashes # end hashes # end hashes # end hashes # end hashes # end hashes # end hashes

async def czrCrypt(message, chrset, czrkey):

    def czrEncode(letter, chrset, czrkey):

        lenChrSet = len(chrset)

        pos = chrset.find(letter)

        newpos = pos + czrkey

        if newpos >= lenChrSet:
            newpos = newpos - lenChrSet

        elif newpos < 0:
            newpos = newpos + lenChrSet

        return chrset[newpos]

    output = ''

    for character in message:
        if character in chrset:
            output = output + czrEncode(character, chrset, czrkey)
        else:
            output = output + character

    return(output)

async def fernetCyther(message, key, mode):

    f = Fernet(key)

    if mode in modesForE:

        message = message.encode()

        message = f.encrypt(message)

        message = message.decode()

        return(message)

    elif mode in modesForD:

        try:

            message = message.encode()

            message = f.decrypt(message)

            message = message.decode()

            return(message)

        except:

            return('incorect key or encrypted string')

# hash methods end # hash methods end # hash methods end # hash methods end # hash methods end # hash methods end # hash methods end

async def checkPerm(role, ctx):
    if role in [i.name.lower() for i in ctx.message.author.roles]:
        return True
    else:
        await noPermission(ctx)
        return False

async def noPermission(ctx):
    await ctx.send(f"Try me, {ctx.message.author.name}")

def isAdmin(ctx):
    if str(ctx.message.author) in botAdmins:
        return True
    else:
        # await ctx.send("Try me, " + str(ctx.message.author))
        return False

async def log(message):

    channel = client.get_channel(logServerId)
    await channel.send(message)

async def log2fbServer(message):

    channel = client.get_channel(FBServerId)
    await channel.send(message)


# Users control commands

def writeUsers(users):
    if isAdmin():
        with open("discordcmddata.json", "w") as f:
            json.dump(users, f, indent=4)

def getUsers():
    with open("discordcmddata.json", "r") as f:
        content = f.read()
        users = json.loads(content)
        return users

@client.command(name="createuser")
async def doCreateUser(ctx, username):
    if isAdmin(ctx):
        await createUser(username)

async def createUser(username):
    users = getUsers()
    if not username in users:
        users[username] = dict()
        writeUsers(users)

@client.command()
async def removeUser(ctx, username):
    if isAdmin(ctx):
        users = getUsers()
        if username in users:
            del users[username]
            writeUsers(users)

@client.command()
async def getUserAllInfo(ctx, username):
    if isAdmin(ctx):
        users = getUsers()
        for name, info in users.items():
            if name == username:
                return info

@client.command()
async def getUserInfo(ctx, username, infoname):
    if isAdmin(ctx):
        users = getUsers()
        for name, info in users.items():
            if name == username and infoname in info:
                return info[infoname]

@client.command()
async def setUserInfo(ctx, username, varname, varvalue):
    if isAdmin(ctx):
        users = getUsers()
        for name, info in users.items():
            if name == username:
                if len(info) >= datalimit and not varname in info:
                    for i in info:
                        first = i
                        break
                    del info[i]
                    info[varname] = varvalue
                    users[name] = info
                else:
                    info[varname] = varvalue
                    users[name] = info
        writeUsers(users)

@client.command()
async def resetUserInfo(ctx, username):
    if isAdmin(ctx):
        users = getUsers()
        for name, info in users.items():
            if name == username:
                users[name] = dict()
                writeUsers(users)

# end of user control

# end of defs # end of defs # end of defs # end of defs # end of defs # end of defs # end of defs # end of defs # end of defs # end of defs

@client.event
async def on_ready():

    print(f'Bot is online\n')

    await log("bot has booted and no errors ocured")

    await tactical_pause(0)

@client.event
async def on_message(msg):
    if msg.content.startswith(".secret"):
        await msg.channel.send("the thruth is..")
        await asyncio.sleep(2)
        await msg.channel.send("you failed to get it")

    await client.process_commands(msg)

@client.event
async def on_member_join(member):
    pass

@client.command(name = "eval")
async def _eval(ctx, *, code):
    if isAdmin(ctx):
        try:
            out = eval(ctx.message.content[len(commandPrefix) + 5:])
            await ctx.send(out)
        except Exception as e:
            await ctx.send(e)

@client.command()
async def reboot(ctx):

    if str(ctx.message.author) in botAdmins:

        await ctx.send('bye ~CryptoBot')

        try:
            os.startfile(__file__)
        except:

            subprocess.call(__file__)

        await client.change_presence(activity=discord.Game(name='rebooting . . .'))

        exit()

    else:
        print(f'{str(ctx.message.author())} tried and failed to pull {__file__} down')

@client.command()
async def source(ctx):
    await ctx.send("Gathering source code..")
    try:
        with open(__file__, "r") as f:
            c = f.read()

            c = c.replace('```', '` ` ` `') # this removes any formating isuses

            parts = c.split("a" + "s" + "ync def " or '# ' + 'split ' + 'here')

            print("```python\n" + parts[0] + "\n```")

            try:
                await ctx.send("```python\n" + parts[0] + "\n```")
            except Exception as e:
                await ctx.send(f'an error ocoured\n```\n{e}\n```')

            parts.pop(0)

            doCmd = False
            doEvt = False
            toCmd = ""
            toEvt = ""

            for part in parts:
                msg = "```python\n"

                if doCmd:
                    msg += toCmd
                    doCmd = False

                if doEvt:
                    msg += toEvt
                    doEvt = False

                if "@client.command(" in part:
                    toCmd = part[part.index("@client.command("):]
                    part = part[:-len(toCmd)]
                    doCmd = True

                if "@client.even" + "t" in part:
                    toEvt = part[part.index("@client.even" + "t"):]
                    part = part[:-len(toEvt)]
                    doEvt = True

                msg += "a" + "s" + "ync def " + part + "\n```"

                try:

                    await ctx.send(msg)

                except Exception as e:

                    await ctx.send(f"Could not gather source code!\n```{e}```\ngoto `https://github.com/Equilibris/Discord-Hack-Week-Harpocrates/blob/master/bot.py` for the full source")

    except Exception as e:
        await ctx.send(f"Could not gather source code!\n```{e}```")

@client.command()
async def hardstop(ctx):
    if isAdmin(ctx):

        await client.change_presence(activity=discord.Game(name='HARDSTOP DETECTED'))

        exit()

@client.command()
async def stop(ctx):
    if isAdmin(ctx):
        await client.close()

@client.command()
async def dmMe(ctx, *, message = 'passed'):

    await ctx.message.author.send(message)

# start crypto commads # start crypto commads # start crypto commads # start crypto commads # start crypto commads # start crypto commads # start crypto commads

@client.command()
async def allSets(ctx, *, com = 'PASSED for auto fail'):

    arg=[

        'chrsets',
        'hashes',
        'modes'

    ]

    com = str(com)

    if com.lower() == 'czr':

        chrsetslist = []

        for key in chrsets.keys():
            chrsetslist.append(key)

        await ctx.send(f'hears all our chrsets:\n```\n{chrsetslist}\n```')

    elif com.lower()  == 'hashes':

        await ctx.send(f'hears all our hash algorithms:\n```\n{allHashes}\n```')

    elif com.lower()  == 'modes':

        await ctx.send(f'hears all our modes for encrypting:\n```\n{modesForE}\n```\nand hears all our modes for decrypting:\n```\n{modesForD}\n```')

    elif com.lower() == 'passed for auto fail':

        await ctx.send(f'her\'s a list of all sets:\n```\n{arg}\n```')

    else:

        await ctx.send(f'{com} is not a valid argument for {commandPrefix}allSets, hears a list of all valid arguments:\n```\n{arg}\n```')

@client.command()
async def czrCode(ctx, mode = 'e', chrset = 'ascii', key = 17, *, message = 'MS'):

    mode = str(mode)

    czrkey = int(key)

    chrset = str(chrset)

    if mode in modesForE:

        if chrset.lower() in chrsets.keys():

            chrset = chrsets[chrset.lower()]

            newMessage = await czrCrypt(message, chrset, czrkey)

            await ctx.send(newMessage)

        else:
            await ctx.send(f'chrset \'{chrset}\' does not exsist')

    elif mode in modesForD:

        czrkey *= -1

        if chrset.lower() in chrsets.keys():

            chrset = chrsets[chrset.lower()]

            newMessage = await czrCrypt(message, chrset, czrkey)

            await ctx.send(newMessage)

        else:
            await ctx.send(f'chrset \'{chrset}\'')

    else:
        await ctx.send(f'{mode} is not a mode')

@client.command()
async def fernet(ctx, pwordHashFormula = 'SHA512', mode='e',key='MS', *,message='is quite nice'):

    async def hash(var):
        var = var.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA512(),
            length = 32,
            salt = b'\xe7\xde\xc1\xf0\x81\x99\xde}\xa4\xb50u;&\x06\xe7\xa4\xbfn\xbc',
            iterations = 100000,
            backend = default_backend()
        )

        var3 = base64.urlsafe_b64encode(kdf.derive(var))

        return(var3)

    pwordHashFormula = str(pwordHashFormula)

    pwordHashFormula = pwordHashFormula.upper()

    if pwordHashFormula in allHashes:

        # try:
        #     getattr(hashFunctions, pwordHashFormula)
        # except Exception as e:
        #     await ctx.send(f"```\n{e}\n```")

        if pwordHashFormula == 'MD5':

            key = await MD5(key)

        elif pwordHashFormula == 'SHA512':

            key = await SHA512(key)

        elif pwordHashFormula == 'SHA384':

            key = await SHA384(key)

        elif pwordHashFormula == 'SHA256':

            key = await SHA256(key)

        elif pwordHashFormula == 'SHA224':

            key = await SHA224(key)

        elif pwordHashFormula == 'SHA3_224':

            key = await SHA3_224(key)

        elif pwordHashFormula == 'SHA3_256':

            key = await SHA3_256(key)

        elif pwordHashFormula == 'SHA3_384':

            key = await SHA3_384(key)

        elif pwordHashFormula == 'SHA3_512':

            key = await SHA3_512(key)

        elif pwordHashFormula == 'SHA512':

            key = await SHA512(key)

        elif pwordHashFormula == 'SHA512_224':

            key = await SHA512_224(key)

        elif pwordHashFormula == 'SHA512_256':

            key = await SHA512_256(key)

        elif pwordHashFormula == 'SHAKE128':

            key = await SHAKE128(key)

        elif pwordHashFormula == 'SHAKE256':

            key = await SHAKE256(key)

        else:

            await log(f'{pwordHashFormula} has no reg entry')

    else:

        key = await hash(key)

        await ctx.send(f'{pwordHashFormula} is not a  recognised hash formula hears a list of all our hashes: \n{allHashes}\n you are now using a stepin hash (sha512)')

    output = await fernetCyther(message, key, mode)

    await ctx.send(output)

@client.command()
async def pulseLock(ctx, *, PLinput = 'passed'):

    await ctx.send('pulseLock is a WIP cryptography programing / pipeline syntax language')

    await czrCode(ctx, 'e', 'ascii', '17', 'syntax error')

# end crypto commads # end crypto commads # end crypto commads # end crypto commads # end crypto commads # end crypto commads # end crypto commads

@client.command()
async def ping(ctx):
    await ctx.send(f'my ping is {round(client.latency *1000)}ms')

    await log(f'\nping to server `{ctx.message.guild}` is `{client.latency *1000}ms`')

@client.command()
async def FB(ctx, message = 'passed'):

    if message != 'passed':

        await log2fbServer(f'\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\n```\nauthor = {ctx.message.author}, server =  {ctx.message.guild}\n```\n```\n{message}\n```')

@client.command()
async def man(ctx, *, com = 'passed'):

    allcoms = [

        'help',
        'source',
        'dmMe',
        'allSets',
        'czrCode',
        'fernet',
        'man',
        'FB',
        'ping'


    ]

    if com == 'passed':
        await ctx.send(f'heres all our manual entrys\n```\n{allcoms}\n```')

    elif com == 'help':
        await ctx.send(f'```\nHelp displays a list of all commands and a simple description of how to use them\n```')

    elif com == 'source':
        await ctx.send(f'```\nSource gathers source code through the help of opening self and replacing confidential information and series of three ` to make a uniform output\n```')

    elif com == 'dmMe':
        await ctx.send(f'```\nOpens a dm channel between @{ctx.message.author}/the author of this massage and myself \n```')

    elif com == 'allSets':
        await ctx.send(f'```\nSends a list of all types in a set for example all hashes\n```')

    elif com == 'czrCode':
        await ctx.send(f'```\nczrCode runs a Caesar encryption method on the input message. This takes in arguments: Mode which is a Harpocrates mode class (you can view all modes with command {commandPrefix}allsets modes). Character set aka alphabet used, this must be common with the both message and the expected output this is a Harpocrates chrSet class (you can view all chrSet with command {commandPrefix}allsets chrSet). Key which is a standard integer / whole number. Message which is just a normal string which can include spaces. You can learn more abought Caesar ciphers in https://en.wikipedia.org/wiki/Caesar_cipher\n```')

    elif com == 'fernet':
        await ctx.send(f'```\nfernet runs a fernet encryption on the input message. This takes in arguments: Hash which is a Harpocrates hash method (you can view all hash methods with command {commandPrefix}allsets hashs). Mode which is a Harpocrates mode class (you can view all modes with command {commandPrefix}allsets modes). Key  which is just a normal string which CAN NOT include spaces. Message which is just a normal string which can include spaces. You can learn more abought Caesar ciphers in https://cryptography.io/en/latest/fernet/ or https://en.wikipedia.org/wiki/Symmetric-key_algorithm but this is a much broader topic than the python documentation \n```')

    elif com == 'man':
        await ctx.send(f'```\ngets a manual entry on a command from {allcoms}. This takes in argument com which is the command you are using in your search \n```')

    elif com == 'FB':
        await ctx.send(f'```\nSends feedback to my devs, this can be everything from bugreports to new chrsets (for example if you have a alphabet we do not include for example French, Japanese or Russian, if you do please send in this format: .FB your username and tag(so we can dm you once we have added it) name of alphabet then the entire alphabet in lowercase then /// and then entire alphabet in uppercase then /// then all the numbers in order lowest (0) to highest). This takes in argument Message which is just a normal string which can include spaces\n```')

    elif com == 'ping':
        await ctx.send(f'```\nSends ping in ms\n```')

@client.command()#name = 'help')
async def help(ctx):

    commands = [

        [f'{commandPrefix}help', 'shows help'],
        [f'{commandPrefix}source', 'sends the entire source in the channel'],
        [f'', 'requesing it'],
        [f'{commandPrefix}dmMe', 'dm\'s the author of the message'],
        [f'', '(just for testing)'],
        [f'{commandPrefix}allSets set', 'sends a list of all sets for set'],
        [f'{commandPrefix}czrCode mode chrset key M', 'Cesar encrypts M by theversing'],
        [f' ', 'the chrset with key message'],
        [f'{commandPrefix}fernet HASH mode key M', 'encrypts M with key after'],
        ['','it has been hashed with algorithm HASH'],
        [f'{commandPrefix}man arg', 'opens manual on command arg'],
        [f'{commandPrefix}FB feedback', 'sends feedback or reports a bug to'],
        ['','FB server'],
        [f'{commandPrefix}ping', 'shows ping']

    ]

    msg = "```\nThis is a list of all our commands\n\n"

    for i in commands:
        msg += i[0] + " " * (30 - len(i[0])) + i[1] + "\n"

    msg = msg[:-1] + "\n```"

    await ctx.send(msg)
    print(f'\nhelp ls in {ctx}')

client.run(token)
