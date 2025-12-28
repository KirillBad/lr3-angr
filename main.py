import angr
from angr import SimState
import claripy


def is_successful(state: SimState) -> bool:
    stdout_output = state.posix.dumps(1)
    return b"entered is valid" in stdout_output


def is_failed(state: SimState) -> bool:
    stdout_output = state.posix.dumps(1)
    return b"wrong" in stdout_output or b"is not valid" in stdout_output


def solve_blind() -> bytes | None:
    proj = angr.Project("./LR3_var2.exe", auto_load_libs=False)

    input_chars = [claripy.BVS(name=f"byte_{i}", size=8) for i in range(11)]

    input_bvs = claripy.Concat(*input_chars)

    state = proj.factory.entry_state(stdin=input_bvs)

    for byte in input_chars:
        state.solver.add(
            claripy.Or(
                claripy.And(byte >= 32, byte <= 126),
                byte == 0,
                byte == 10,
            )
        )

    simgr = proj.factory.simulation_manager(thing=state)

    simgr.explore(find=is_successful, avoid=is_failed)

    if simgr.found:
        return simgr.found[0].solver.eval_atleast(input_bvs, 3, cast_to=bytes)


if __name__ == "__main__":
    print(solve_blind())
