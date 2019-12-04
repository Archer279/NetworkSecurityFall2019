import asyncio
import playground
from playground.network.packet import PacketType
from autograder_ex8_packets import AutogradeStartTest, AutogradeTestStatus, AutogradeResultRequest, AutogradeResultResponse
#from gamepacket import CreateGameInitPacket, CreateGameRequirePayPacket, CreateGamePayPacket, CreateGameResponsePacket, CreateGameCommandPacket
#import gamepacket
from gamepacket import *
import playground.common.logging as pgLog

########################
# Bank stuff
########################
from CipherUtil import loadCertFromFile
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBank import BankClientProtocol, OnlineBankConfig
import getpass, sys, os

certPath = os.path.join("bank.cert")
bank_cert = loadCertFromFile(certPath)
bank_addr = '20194.0.0.19000'
bank_port = 777



# Setup logging right away
pgLog.EnablePresetLogging(pgLog.PRESET_VERBOSE)

SERVER_PORT = 3088
#AG_IP   = '192.168.200.52'
AG_IP   = '20194.0.0.19000'
AG_PORT = 19008


GET_HAMMER = ['look', 'look mirror', 'get hairpin', 'look chest', 'unlock chest with hairpin', 'open chest', 'look in chest', 'get hammer from chest'] 
ESCAPE = ['get key', 'unlock door with key', 'open door']
HIT = 'hit flyingkey with hammer'


async def send_payment(client, bank_client, src, dst, amount, memo):
    await playground.create_connection(
            lambda: bank_client,
            bank_addr,
            bank_port,
            family='default'
        )
    print("Connected. Logging in.")
        
    try:
        await bank_client.loginToServer()
    except Exception as e:
        print("Login error. {}".format(e))
        return False

    try:
        await bank_client.switchAccount(src)
    except Exception as e:
        print("Could not set source account as {} because {}".format(
            src,
            e))
        return False
    
    try:
        result = await bank_client.transfer(dst, amount, memo)
    except Exception as e:
        print("Could not transfer because {}".format(e))
        return False
        
    print(f"Transfer completed:\n\treceipt: {result.Receipt}\n\tsignature:{result.ReceiptSignature}")
    client.write(create_game_pay_packet(result.Receipt, result.ReceiptSignature))
    return result


def deal_with_input(client, packet):
    if type(packet) is AutogradeTestStatus:
        if client.state == "init":
            client.state = "command"

        print("""Contents:
        test_id: {0}
        submit_status: {1}
        client_status: {2}
        server_status: {3}
        error: {4}
        """.format(packet.test_id,packet.submit_status,packet.client_status,packet.server_status,packet.error))
        if packet.submit_status != 1:
            print("ERROR!!!!!")
        if packet.client_status == 1:
            pass
        if packet.server_status == 1:
            pass
        client.write(create_game_init_packet('wwang123'))
    elif isinstance(packet, CreateGameRequirePayPacket):
        uid, account, amount = process_game_require_pay_packet(packet)
        # Process payments
        #print("Begin transfer")
        result = asyncio.ensure_future(send_payment(client, client.bank_client, 'wwang123_account', account, amount, uid))
        #await result
        #print(f"Transfer completed:\n\treceipt: {result.Receipt}\n\tsignature:{result.ReceiptSignature}")
        #client.write(create_game_pay_packet(result.Receipt, result.ReceiptSignature))
    elif isinstance(packet, CreateGameResponsePacket):
        response, status = process_game_response(packet)
        print("""Game Response Packet:
        response: {0}
        status: {1}""".format(response,status))
        if client.state == "command":
            if client.step < len(GET_HAMMER):
                mypacket = create_game_command(GET_HAMMER[client.step])
                client.write(mypacket)
                print(f"Sending: {process_game_command(mypacket)}")
                client.step += 1
            else:
                client.step = 0
                client.state = "hammertime"
        elif client.state == "hammertime":
            if "to the wall" in response:
                #mypacket = GameCommandPacket.create_game_command_packet(HIT)
                client.write(create_game_command(HIT))
                client.state = "escape"
        elif client.state == "escape":
                #mypacket = GameCommandPacket.create_game_command_packet(ESCAPE[client.step])
                #client.write(mypacket)
                client.write(create_game_command(ESCAPE[client.step]))
                client.step += 1
             
    
class Ex7Client(asyncio.Protocol):
    # States
    STATES = ["init", "command", "client_test", "server_test"]

    def __init__(self, bank_client):
        #self.proceed = False
        self.state = "init"
        self.step = 0
        self.bank_client = bank_client
        pass

    def connection_made(self, transport):
        self.transport = transport
        startPacket = AutogradeStartTest()
        startPacket.name = "Weichen Wang"
        startPacket.team = 1
        startPacket.email = "wwang123@jhu.edu"
        startPacket.port = SERVER_PORT
        with open("gamepacket.py", "rb") as f:
            startPacket.packet_file = f.read()
        
        transport.write(startPacket.__serialize__())
        print("Connected. Packet sent\n{0}".format(startPacket.__serialize__()))

    def data_received(self, data):
        # data is now in terms of packets
        inPackets = PacketType.Deserializer()
        inPackets.update(data)
        
        packs = list(inPackets.nextPackets())
        for pack in packs:
            print(pack)
            deal_with_input(self, pack)

        
        #lines = data.decode().split("<EOL>\n")
        #for line in lines:
        #    if not line: continue
        #    #if not proceed: break
        #    print(line)
        #    deal_with_input(self, line)
                
                

    def write(self, msg):
        #msg += "<EOL>\n"
        #self.transport.write(msg.encode())
        print("Data to send: {}".format(msg))
        self.transport.write(msg.__serialize__())

    def connection_lost(self):
        print("Disconnected")    

if __name__ == "__main__":
    username = 'wwang123'
    password = 'Netsecurity3308'
    bank_client = BankClientProtocol(bank_cert, username, password) 
    loop = asyncio.get_event_loop()
    coro = playground.create_connection(lambda: Ex7Client(bank_client), AG_IP, AG_PORT)
    client = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
        
    client.close()
    loop.run_until_complete(client.close())
    loop.close()
