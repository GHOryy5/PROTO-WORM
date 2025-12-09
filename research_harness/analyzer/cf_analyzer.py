import angr
import pygraphviz as pgv
import os
import logging

logging.getLogger('angr').setLevel(logging.ERROR)

class ControlFlowAnalyzer:
    """
    Analyzes a binary file using Angr to generate a Control Flow Graph (CFG),
    highlighting the path that led to a specific crash address.
    """
    def __init__(self, binary_path):
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Target binary not found: {binary_path}")
        self.proj = angr.Project(binary_path, auto_load_libs=False)
        print(f"[CFG] Loaded project: {binary_path}")

    def analyze_crash_path(self, func_address, crash_address):
        """
        Generates a CFG for a function and attempts to find the path to the crash address.
        :param func_address: The entry point of the vulnerable function.
        :param crash_address: The instruction pointer (IP) at the moment of the crash.
        """
        print(f"[CFG] Analyzing function at 0x{func_address:x}...")
        
        cfg = self.proj.analyses.CFGFast()
        
        # Find the function object
        target_func = cfg.kb.functions.get(func_address)
        if not target_func:
            print(f"[ERROR] Function 0x{func_address:x} not found in binary.")
            return None

        # Build the graph and highlight the crash block
        graph = pgv.AGraph(directed=True)
        
        # Create a dictionary to map node addresses to their Graphviz ID
        addr_to_node = {}

        # Add all basic blocks in the function to the graph
        for block_addr in target_func.block_addrs:
            block = cfg.get_any_node(block_addr)
            if not block: continue
            
            node_id = f"0x{block_addr:x}"
            addr_to_node[block_addr] = node_id
            
            # Highlight the block containing the crash address
            color = 'black'
            if block_addr <= crash_address < block_addr + block.size:
                color = 'red'
                print(f"[CFG] Identified crash block at 0x{block_addr:x}")

            graph.add_node(node_id, 
                           label=f"Block @ {node_id}\n{block.size} bytes",
                           shape='box',
                           color=color,
                           fontcolor=color)

        # Add edges (Control Flow)
        for src_addr, node_id in addr_to_node.items():
            for dst_addr in self._get_successors(cfg, src_addr):
                if dst_addr in addr_to_node:
                    graph.add_edge(node_id, addr_to_node[dst_addr])

        return graph

    def _get_successors(self, cfg, addr):
        """Helper to get all successor addresses from a basic block."""
        node = cfg.get_any_node(addr)
        if node:
            return [n.addr for n in node.successors]
        return []

    def save_graph(self, graph, filename="crash_path.dot", image_format="png"):
        """Saves the graph to a DOT file and renders it to an image."""
        if graph:
            graph.write(filename)
            print(f"[CFG] DOT graph saved to {filename}")
            try:
                graph.draw(f"{filename}.{image_format}", prog='dot')
                print(f"[CFG] Image rendered to {filename}.{image_format}")
            except Exception as e:
                print(f"[WARN] Failed to render image. Is pygraphviz configured correctly? Error: {e}")

# Example usage demonstrating the intent:
if __name__ == '__main__':
    # This would typically be a proprietary ATM/ICS DLL/firmware file.
    # We use /bin/ls as a placeholder for demonstration.
    target_bin = "/bin/ls" 
    
    # These addresses are placeholders; they would come from the crash dump.
    # func_addr: The start of the function where the crash occurred.
    # crash_addr: The Instruction Pointer (IP) at the crash site.
    FUNCTION_ADDRESS = 0x400000 
    CRASH_ADDRESS = 0x400060 
    
    try:
        analyzer = ControlFlowAnalyzer(target_bin)
        cfg_graph = analyzer.analyze_crash_path(FUNCTION_ADDRESS, CRASH_ADDRESS)
        if cfg_graph:
            analyzer.save_graph(cfg_graph)
    except Exception as e:
        print(f"FATAL ERROR during analysis: {e}")
