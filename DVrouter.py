####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

import json
from router import Router
from packet import Packet

class DVrouter(Router):
    """Distance vector routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.dv = {addr: (0, None)}  # Distance vector: dest -> (cost, port)
        self.forwarding_table = {}
        self.neighbors = {}          # port -> (neighbor_addr, cost)
        self.neighbors_dv = {}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            # Data packet
            if packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                self.send(out_port, packet)
        else:
            # Routing packet
            changed = False
            src = packet.src_addr
            # Parse JSON string content to dict
            dv_from_neighbor = json.loads(packet.content)
            cost_to_neighbor = self.neighbors[port][1]

            for dest, neighbor_cost in dv_from_neighbor.items():
                # Xử lý trường hợp chi phí vô cùng
                if neighbor_cost == float('inf') or cost_to_neighbor == float('inf'):
                    total_cost = float('inf')
                else:
                    total_cost = cost_to_neighbor + neighbor_cost

                if dest not in self.dv or total_cost < self.dv[dest][0]:
                    self.dv[dest] = (total_cost, port)
                    changed = True
                elif self.dv[dest][1] == port and total_cost != self.dv[dest][0]:
                    self.dv[dest] = (total_cost, port)
                    changed = True

            if changed:
                self._update_forwarding_table()
                self._broadcast_dv()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.neighbors[port] = (endpoint, cost)
        if endpoint not in self.dv or cost < self.dv[endpoint][0]:
            self.dv[endpoint] = (cost, port)

        self._update_forwarding_table()
        self._broadcast_dv()

    def _update_forwarding_table(self):
        self.forwarding_table = {}
        for dst, (cost, port) in self.dv.items():
            # Không thêm vào bảng định tuyến các điểm đến có chi phí vô cùng
            if cost != float('inf'):
                self.forwarding_table[dst] = port

    def _broadcast_dv(self):
        """Send DV to all neighbors."""
        for port, (neighbor, _) in self.neighbors.items():
            vector = {dst: cost for dst, (cost, _) in self.dv.items()}
            pkt = Packet(Packet.ROUTING, self.addr, neighbor, content=json.dumps(vector))
            #print(f"[{self.addr}] Sending DV to {neighbor} on port {port}: {vector}")
            self.send(port, pkt)

    def handle_remove_link(self, port):
        """Handle removed link."""
        if port in self.neighbors:
            endpoint, cost = self.neighbors.pop(port)

            # Xóa tất cả các entry dv mà đi qua port bị mất
            to_delete = []
            for dest, (c, p) in self.dv.items():
                if p == port:
                    to_delete.append(dest)

            for dest in to_delete:
                del self.dv[dest]

            # Đồng thời xóa entry endpoint nếu đi qua port đó
            if endpoint in self.dv and self.dv[endpoint][1] == port:
                del self.dv[endpoint]

            self._update_forwarding_table()
            self._broadcast_dv()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_dv()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return f"DVrouter(addr={self.addr})"
