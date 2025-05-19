####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

import json
from router import Router
from packet import Packet

class DVrouter(Router):


    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Khởi tạo lớp cha
        self.heartbeat_time = heartbeat_time # Thời gian gửi bản tin định kỳ
        self.last_time = 0 # Thời điểm gửi bản tin định kỳ cuối cùng

        self.INF = 16 # Giá trị vô cùng hữu hạn (số bước nhảy tối đa)

        # Bảng khoảng cách: đích -> (chi phí, cổng)
        # Khởi tạo: chi phí đến chính nó là 0, các đích khác coi như vô cùng ban đầu
        self.dv = {addr: (0, None)}

        # Bảng chuyển tiếp: đích -> cổng (được suy ra từ bảng DV)
        self.forwarding_table = {}

        # Thông tin láng giềng: cổng -> (địa chỉ láng giềng, chi phí liên kết)
        self.neighbors = {}


    def handle_packet(self, port, packet):
        """Xử lý gói tin nhận được từ một cổng."""
        if packet.is_traceroute:
            # Gói tin dữ liệu
            if packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                # Đảm bảo cổng ra vẫn hợp lệ
                if out_port in self.neighbors:
                    self.send(out_port, packet)
            # Gói tin dữ liệu đến đích không rõ -> hủy (mặc định)
        else:
            # Gói tin định tuyến (DV) từ láng giềng
            changed = False
            # Kiểm tra liên kết còn tồn tại
            if port not in self.neighbors: return

            cost_to_neighbor = self.neighbors[port][1]

            try:
                dv_from_neighbor = json.loads(packet.content)
            except json.JSONDecodeError:
                # Bỏ qua gói tin định tuyến lỗi
                return

            # Cập nhật bảng DV dựa trên thông tin từ láng giềng
            for dest, neighbor_cost_raw in dv_from_neighbor.items():
                # Chuyển chi phí láng giềng sang định dạng vô cùng nội bộ
                neighbor_cost = self.INF if (neighbor_cost_raw == float('inf') or neighbor_cost_raw >= self.INF) else neighbor_cost_raw

                # Tính tổng chi phí qua láng giềng, giới hạn bằng INF
                if cost_to_neighbor >= self.INF or neighbor_cost >= self.INF:
                     total_cost = self.INF
                else:
                     total_cost = cost_to_neighbor + neighbor_cost
                     if total_cost > self.INF: # Giới hạn tổng chi phí
                         total_cost = self.INF

                # Logic cập nhật bảng DV (Bellman-Ford)
                current_cost, current_next_hop_port = self.dv.get(dest, (self.INF, None)) # Lấy thông tin hiện tại, mặc định là vô cùng

                # 1. Tìm thấy đường đi tốt hơn (chi phí thấp hơn)
                if total_cost < current_cost:
                    self.dv[dest] = (total_cost, port)
                    changed = True
                # 2. Chi phí đường đi HIỆN TẠI qua láng giềng này thay đổi (tăng hoặc giảm)
                elif current_next_hop_port == port and total_cost != current_cost:
                    self.dv[dest] = (total_cost, port)
                    changed = True
                # 3. Đích đang không tới được (chi phí >= INF), nhưng láng giềng báo có đường tới được (chi phí < INF)
                elif current_cost >= self.INF and total_cost < self.INF:
                     self.dv[dest] = (total_cost, port)
                     changed = True
                # Các trường hợp khác: không cập nhật (ví dụ: đường đi mới đắt hơn, hoặc bằng chi phí nhưng qua láng giềng khác)


            if changed:
                self._update_forwarding_table() # Cập nhật bảng chuyển tiếp
                self._broadcast_dv() # Phát tán bảng DV mới

    def handle_new_link(self, port, endpoint, cost):
        """Xử lý khi một liên kết mới được thiết lập."""
        cost = min(cost, self.INF) # Giới hạn chi phí liên kết ban đầu

        self.neighbors[port] = (endpoint, cost)

        # Cập nhật đường đi trực tiếp đến láng giềng mới nếu nó tốt hơn
        if endpoint not in self.dv or cost < self.dv[endpoint][0]:
             self.dv[endpoint] = (cost, port)
             self._update_forwarding_table() # Cập nhật FT
             self._broadcast_dv() # Phát tán DV mới
        else:
             # Nếu chỉ thêm láng giềng mà chi phí không tốt hơn, vẫn cần phát tán
             # DV để láng giềng mới học về các đường đi qua router này.
             self._broadcast_dv()


    def _update_forwarding_table(self):
        """Xây dựng lại bảng chuyển tiếp từ bảng DV."""
        self.forwarding_table = {}
        for dst, (cost, port) in self.dv.items():
            # Chỉ thêm các đích có thể tới được (chi phí < INF) và có cổng hợp lệ
            if cost < self.INF and port is not None:
                self.forwarding_table[dst] = port
            # Không thêm entry cho chính router này vào bảng chuyển tiếp


    def _broadcast_dv(self):
        """Gửi bảng DV cho tất cả láng giềng (áp dụng Poisoned Reverse)."""
        for port, (neighbor_addr, link_cost) in self.neighbors.items():
            # Tạo bản tin DV riêng cho từng láng giềng
            vector_to_send = {}
            for dest, (cost, next_hop_port) in self.dv.items():
                # Poisoned Reverse: Nếu đường đi tốt nhất đến 'dest' là THÔNG QUA láng giềng này,
                # báo chi phí là VÔ CÙNG cho láng giềng đó.
                if next_hop_port == port:
                    vector_to_send[dest] = self.INF
                else:
                    # Ngược lại, báo chi phí thực tế.
                    vector_to_send[dest] = cost

            # Gửi bản tin DV đã chỉnh sửa cho láng giềng
            pkt_content = json.dumps(vector_to_send)
            pkt = Packet(Packet.ROUTING, self.addr, neighbor_addr, content=pkt_content)
            self.send(port, pkt)


    def handle_remove_link(self, port):
        """Xử lý khi một liên kết bị gỡ bỏ."""
        if port in self.neighbors:
            endpoint, old_cost = self.neighbors.pop(port)
            changed = False

            # Đánh dấu các đường đi mà bước nhảy kế tiếp là cổng này là VÔ CÙNG
            for dest, (cost, p) in list(self.dv.items()): # Lặp trên bản sao để sửa đổi
                 if p == port:
                     # Đặt chi phí vô cùng, không có next hop hợp lệ
                     self.dv[dest] = (self.INF, None)
                     changed = True
                 # Cả đường đi trực tiếp đến láng giềng vừa mất (nếu nó dùng cổng này)
                 if dest == endpoint and p == port:
                      self.dv[dest] = (self.INF, None)
                      changed = True

            # Sau khi cập nhật bảng DV (đánh dấu vô cùng)
            if changed:
                self._update_forwarding_table() # Cập nhật FT
                self._broadcast_dv() # Phát tán bảng DV đã thay đổi

    def handle_time(self, time_ms):
        """Xử lý sự kiện thời gian (gửi bản tin định kỳ)."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_dv() # Phát tán DV định kỳ

    def __repr__(self):
        """Biểu diễn router, hữu ích cho gỡ lỗi."""
        # Hiển thị bảng DV và FT để dễ kiểm tra
        dv_repr = {k: (f"{v[0]:.2f}" if v[0] < self.INF else "INF", v[1]) for k, v in self.dv.items()}
        ft_repr = {k: v for k, v in self.forwarding_table.items()}
        return f"DVrouter(addr={self.addr}, dv={dv_repr}, ft={ft_repr})"