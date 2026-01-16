import argparse
import inspect
import secrets
from pathlib import Path
from typing import TypeVar, Callable, Awaitable, Union, overload, cast
from python.helpers import dotenv, rfc, settings, files
import asyncio
import threading
import queue
import sys
import subprocess
import time

T = TypeVar("T")
R = TypeVar("R")

parser = argparse.ArgumentParser()
args = {}
dockerman = None
runtime_id = None


def initialize():
    global args
    if args:
        return
    parser.add_argument("--port", type=int, default=None, help="Web UI port")
    parser.add_argument("--host", type=str, default=None, help="Web UI host")
    parser.add_argument(
        "--cloudflare_tunnel",
        type=bool,
        default=False,
        help="Use cloudflare tunnel for public URL",
    )
    parser.add_argument(
        "--development", type=bool, default=False, help="Development mode"
    )

    known, unknown = parser.parse_known_args()
    args = vars(known)
    for arg in unknown:
        if "=" in arg:
            key, value = arg.split("=", 1)
            key = key.lstrip("-")
            args[key] = value


def get_arg(name: str):
    global args
    return args.get(name, None)


def has_arg(name: str):
    global args
    return name in args


def is_dockerized() -> bool:
    return bool(get_arg("dockerized"))


def is_development() -> bool:
    return not is_dockerized()


def get_local_url():
    if is_dockerized():
        return "host.docker.internal"
    return "127.0.0.1"


def get_runtime_id() -> str:
    global runtime_id
    if not runtime_id:
        runtime_id = secrets.token_hex(8)
    return runtime_id


def get_persistent_id() -> str:
    id = dotenv.get_dotenv_value("A0_PERSISTENT_RUNTIME_ID")
    if not id:
        id = secrets.token_hex(16)
        dotenv.save_dotenv_value("A0_PERSISTENT_RUNTIME_ID", id)
    return id


@overload
async def call_development_function(
    func: Callable[..., Awaitable[T]], *args, **kwargs
) -> T: ...


@overload
async def call_development_function(func: Callable[..., T], *args, **kwargs) -> T: ...


async def call_development_function(
    func: Union[Callable[..., T], Callable[..., Awaitable[T]]], *args, **kwargs
) -> T:
    if is_development():
        url = _get_rfc_url()
        password = _get_rfc_password()
        # Normalize path components to build a valid Python module path across OSes
        module_path = Path(
            files.deabsolute_path(func.__code__.co_filename)
        ).with_suffix("")
        module = ".".join(module_path.parts)  # __module__ is not reliable
        result = await rfc.call_rfc(
            url=url,
            password=password,
            module=module,
            function_name=func.__name__,
            args=list(args),
            kwargs=kwargs,
        )
        return cast(T, result)
    else:
        if inspect.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)  # type: ignore


async def handle_rfc(rfc_call: rfc.RFCCall):
    return await rfc.handle_rfc(rfc_call=rfc_call, password=_get_rfc_password())


def _get_rfc_password() -> str:
    password = dotenv.get_dotenv_value(dotenv.KEY_RFC_PASSWORD)
    if not password:
        raise Exception("No RFC password, cannot handle RFC calls.")
    return password


def _get_rfc_url() -> str:
    set = settings.get_settings()
    url = set["rfc_url"]
    if not "://" in url:
        url = "http://" + url
    if url.endswith("/"):
        url = url[:-1]
    url = url + ":" + str(set["rfc_port_http"])
    url += "/rfc"
    return url


def call_development_function_sync(
    func: Union[Callable[..., T], Callable[..., Awaitable[T]]], *args, **kwargs
) -> T:
    # run async function in sync manner
    result_queue = queue.Queue()

    def run_in_thread():
        result = asyncio.run(call_development_function(func, *args, **kwargs))
        result_queue.put(result)

    thread = threading.Thread(target=run_in_thread)
    thread.start()
    thread.join(timeout=30)  # wait for thread with timeout

    if thread.is_alive():
        raise TimeoutError("Function call timed out after 30 seconds")

    result = result_queue.get_nowait()
    return cast(T, result)


def get_web_ui_port():
    web_ui_port = (
        get_arg("port") or int(dotenv.get_dotenv_value("WEB_UI_PORT", 0)) or 5000
    )
    return web_ui_port


def get_tunnel_api_port():
    tunnel_api_port = (
        get_arg("tunnel_api_port")
        or int(dotenv.get_dotenv_value("TUNNEL_API_PORT", 0))
        or 55520
    )
    return tunnel_api_port


def get_platform():
    return sys.platform


def is_windows():
    return get_platform() == "win32"


def get_terminal_executable():
    if is_windows():
        return "powershell.exe"
    else:
        return "/bin/bash"
        


def execute_local_command(command: str, timeout: int = 60, shell: bool = True) -> dict:
    """
    本地执行系统命令/代码，替代原SSH/RFC远程调用
    :param command: 要执行的命令字符串（如 "python3 -c 'print(\"hello\")'"、"ls -l"）
    :param timeout: 命令执行超时时间（秒）
    :param shell: 是否使用shell执行（推荐True，支持复杂命令拼接）
    :return: 标准化返回结果（与原远程调用格式对齐，避免上游代码报错）
    """
    # 初始化返回结果（严格对齐原RFC/SSH返回格式）
    result = {
        "stdout": "",       # 命令正常输出
        "stderr": "",       # 命令错误输出
        "returncode": -1,   # 执行返回码（0=成功，非0=失败）
        "success": False,   # 自定义标识：是否执行成功
        "execution_time": 0 # 执行耗时（秒）
    }

    try:
        start_time = time.time()
        # 执行本地命令（subprocess核心逻辑）
        proc = subprocess.run(
            command,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",  # 直接解码为字符串，避免字节流处理
            timeout=timeout,
            errors="ignore"    # 忽略编码错误，防止输出特殊字符导致崩溃
        )

        # 填充返回结果
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
        result["returncode"] = proc.returncode
        result["execution_time"] = round(time.time() - start_time, 2)
        # 判定执行成功（返回码0即为成功）
        result["success"] = (proc.returncode == 0)

    except subprocess.TimeoutExpired:
        result["stderr"] = f"错误：命令执行超时（超过 {timeout} 秒）"
    except PermissionError:
        result["stderr"] = "错误：没有执行该命令的权限"
    except Exception as e:
        result["stderr"] = f"错误：命令执行异常 - {str(e)}"

    return result
