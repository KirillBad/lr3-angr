import angr
from angr import SimState
import claripy


def is_successful(state: SimState) -> bool:
    return b"pass is" in state.posix.dumps(1)


def is_failed(state: SimState) -> bool:
    return b"wrong" in state.posix.dumps(1) or b"is not valid" in state.posix.dumps(1)


def solve_blind() -> str | None:
    proj = angr.Project("./LR3_var2.exe", auto_load_libs=False)

    input_chars = [claripy.BVS(f"byte_{i}", 8) for i in range(550)]
    input_bvs = claripy.Concat(*input_chars)

    state = proj.factory.entry_state(stdin=input_bvs)

    simgr = proj.factory.simulation_manager(thing=state)

    simgr.explore(find=is_successful, avoid=is_failed)

    if simgr.found:
        return simgr.found[0].posix.dumps(1).decode()


if __name__ == "__main__":
    print(solve_blind())
