import angr
import re
from angr import SimState
import claripy


def is_successful(state: SimState) -> bool:
    return b"pass is" in state.posix.dumps(1)


def is_failed(state: SimState) -> bool:
    return b"wrong" in state.posix.dumps(1) or b"is not valid" in state.posix.dumps(1)


def show_solutions(
    possible_solution: bytes, raw_output: bool | None = False
) -> bytes | list[bytes]:
    if raw_output:
        return possible_solution

    key_pattern = re.compile(b"\x41[^\x0a]{2}\x2d[^\x0a]{3}\x2d[^\x0a]{3}")
    return key_pattern.findall(possible_solution)


def solve_blind() -> str | None:
    proj = angr.Project("./LR3_var2.exe", auto_load_libs=False)

    input_chars = [claripy.BVS(f"byte_{i}", 8) for i in range(550)]
    input_bvs = claripy.Concat(*input_chars)

    state = proj.factory.entry_state(stdin=input_bvs)

    simgr = proj.factory.simulation_manager(thing=state)

    simgr.explore(find=is_successful, avoid=is_failed)

    if simgr.found:
        print(
            *[
                "".join(chr(byte) if 32 <= byte <= 126 else "?" for byte in solution)
                for solution in show_solutions(
                    possible_solution=simgr.found[0].solver.eval(
                        input_bvs, cast_to=bytes
                    )
                )
            ],
            sep="\n",
        )

        return simgr.found[0].posix.dumps(1).decode()


if __name__ == "__main__":
    print(solve_blind())
