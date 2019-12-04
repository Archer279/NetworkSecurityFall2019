import asyncio, sys
import playground
import escape_room_006 as er
from autograder_ex6_packets import AutogradeStartTest, AutogradeTestStatus, AutogradeResultRequest, AutogradeResultResponse
#from gamepacket import GameCommandPacket, GameResponsePacket
from gamepacket import *
import playground.common.logging as pgLog
from playground.network.packet import PacketType
##############################
from CipherUtil import loadCertFromFile
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBank import BankClientProtocol, OnlineBankConfig
import getpass, sys, os
##############################
certPath = os.path.join("bank.cert")
bank_cert = loadCertFromFile(certPath)
bank_addr = '20194.0.0.19000'
bank_port = 777

# Setup logging right away
pgLog.EnablePresetLogging(pgLog.PRESET_VERBOSE)


SERVER_PORT = 3088
AG_IP       = '192.168.200.52'
AG_PORT     = 19007



def verify(bank_client, receipt_bytes, signature_bytes, dst, amount, memo):
    if not bank_client.verify(receipt_bytes, signature_bytes):
        raise Exception("Bad receipt. Not correctly signed by bank")
    ledger_line = LedgerLineStorage.deserialize(receipt_bytes)
    if ledger_line.getTransactionAmount(dst) != amount:
        raise Exception("Invalid amount. Expected {} got {}".format(amount, ledger_line.getTransactionAmount(dst)))
    elif ledger_line.memo(dst) != memo:
        raise Exception("Invalid memo. Expected {} got {}".format(memo, ledger_line.memo()))
    return True

class Ex7Server(asyncio.Protocol): 
    def __init__(self, bank_client):
        self.bank_client = bank_client
        self.dst = 'wwang123_account'
        self.amount = 5
        self.memo = 'Caster'
        self.state = "not running"
        print("I'm running")    

    def connection_made(self, transport):
        self.transport = transport
        self.state = "init"
        #asyncio.ensure_future(self.play())

    def data_received(self, data):
        pktDeserial = PacketType.Deserializer()
        pktDeserial.update(data)
                
        for pkt in list(pktDeserial.nextPackets()):
            if self.state == "init":
                if isinstance(pkt, CreateGameInitPacket):
                    self.username = process_game_init(pkt)
                    print(f"Received Request: {self.username}")
                    self.state = "needmoney"
                    mypacket = create_game_require_pay_packet(self.memo, self.dst, self.amount)
                    print(mypacket.__serialize__())
                    self.transport.write(mypacket.__serialize__())
                    #self.pkt_write(create_game_require_pay_packet(self.memo, self.dst, self.amount))
            
            elif self.state == "needmoney":
                if isinstance(pkt, CreateGamePayPacket):
                    receipt, receipt_sign = process_game_pay_packet(pkt)
                    print(f"Received Receipt: {receipt}\n{receipt_sign}")
                    self.state = "playing"
                    asyncio.ensure_future(self.play())
                    #if verify(self.bank_client, receipt, receipt_sign, self.dst, self.amount, self.memo):
                    #    self.state = "playing"
                    #    asyncio.ensure_future(self.play())
                    #else:
                    #    self.pkt_write(create_game_response('', 'dead'))
                    #    self.state = "init"
            elif self.state == "playing":
                if isinstance(pkt, CreateGameCommandPacket):
                    command = process_game_command(pkt)
                    if not command: continue
                    print("Received: {}".format(command))
                    output = self.game.command(command)

#    def pkt_write(self, pkt):
#        self.transport.write(pkt.__serialize__())

    def write(self, msg):
        pkt = create_game_response(msg,self.game.status)        
        print(f'Sending: {pkt.get_response()} ::: with status {pkt.get_stat()}')
        #print(f'Sending: {pkt.get_response()} ::: with status {pkt.status()} ::: game_over? {pkt.game_over()}')
        self.transport.write(pkt.__serialize__())

    def connection_lost(self):
        print("Connection close")
    
    async def play(self):
        self.game = er.EscapeRoomGame(output=self.write)
        self.game.create_game()
        self.game.start()
        print("Game started")
        #asyncio.ensure_future(self.game.start())
        await asyncio.wait([asyncio.ensure_future(a) for a in self.game.agents])

def main(args):
    username = 'wwang123'
    password = 'Netsecurity3308'
    bank_client = BankClientProtocol(bank_cert, username, password)
    loop = asyncio.get_event_loop()
    coro = playground.create_server(lambda: Ex7Server(bank_client),'localhost', SERVER_PORT) 
    server = loop.run_until_complete(coro)

    try:
	    loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_close())
    loop.close()

if __name__ == "__main__":
    main(sys.argv[1:])

