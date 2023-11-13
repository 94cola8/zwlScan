import asyncio
import re
import aiohttp
import os
import sys
from bs4 import BeautifulSoup
from ..tree.DirTree import DirTree
import time
import random
from colorama import Fore, Style
from ..io.ColorOutput import ScanOutput
from ..exception.ScanException import *
from urllib.parse import urlparse, urljoin
from random import getrandbits
from .Pages import Page
import difflib


class Controller(object):
    header = {
        'User-agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.8) Gecko/20100722 Firefox/3.6.8',
        'Accept-Language': 'Zh-CN, zh;q=0.8, en-gb;q=0.8, en-us;q=0.8',
        'Accept-Encoding': 'identity',
        'Keep-Alive': '300',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
    }

    def __init__(self, args=None):

        self.args = args
        self.output = ScanOutput()

        self.more_detail = self.args.get_args("vv")
        self.detail = self.more_detail if self.more_detail else self.args.get_args("v")
        self.init_url = self.args.get_args("url")

        self.protocol, self.netloc, self.path = self.__parse_url(self.init_url)
        self.prefix = self.protocol + "://" + self.netloc

        self.fuzz_base = self.args.get_args("base")
        if self.fuzz_base is None:
            self.fuzz_prefix = self.init_url if self.init_url[-1] == "/" else self.init_url + "/"
        else:
            self.fuzz_base = self.fuzz_base if self.fuzz_base[-1] == "/" else self.fuzz_base + "/"
            self.fuzz_prefix = urljoin(self.prefix, self.fuzz_base)

        self.queue = asyncio.Queue()
        self.tree = DirTree()
        self._404_page = None
        self.urls = []
        self.time_out_times = 0
        self.map_finish = False
        self.map = self.args.get_args('map')
        self.fuzz = self.args.get_args('fuzz')
        self.work_path = self.args.get_args('work_path')
        self.not_found_flag = self.args.get_args("not_found")
        self.timeout = self.args.get_args('timeout')
        self.start_time = None

        self.__init_ua()
        self.loop = asyncio.get_event_loop()
        self.session = aiohttp.ClientSession(loop=self.loop)

        self.fuzz_num = 0
        self.fuzz_progress = 0
        self.__init_fuzz_list(os.path.join(self.args.get_args("base_path"), "fuzz", "dirList.txt"))
        self.max_threads = self.args.get_args("max_num")
        self.alive_routine = self.args.get_args("max_num")

        self.output.print_banner()
        self.last_proceed_url = None

    # 根据协议域名分割url
    def __parse_url(self, _url):
        url = _url[:-1] if _url[-1] == "/" else _url
        try:
            protocol, netloc, path, query = re.findall("(.*?)://([^/]+)?(/?[^\?]*)?(\??.*)?$", url)[0]
        except Exception:
            self.output.print_error("Parameter url format error. e.g http://www.example.com")
            sys.exit(1)
        return protocol, netloc, path if path != "" else "/"

    # 随机读取UA
    def __init_ua(self):
        path = os.path.join(self.args.get_args("base_path"), "fuzz", "user_agent.txt")
        with open(path, "r") as file:
            self.UA = list(map(lambda x: x[:-1], file.readlines()))

    # 初始化第一个页面，并存入Tree
    def __init__crawler_list(self):
        self.loop.run_until_complete(self.__page_url_collect(self.init_url, init_page_flag=True))

    # 生成 404 页面
    def __init__404_page(self):
        _404_url = urljoin(self.prefix, self.getrandhex(random.randint(40, 50)))
        self.loop.run_until_complete(self.process_404(_404_url))

    async def process_404(self, url):
        try:
            _404_res = await self.get_response(url, allow_redirects=True, timeout=self.timeout)
        except asyncio.TimeoutError:
            self.output.print_warning("Init 404 page timeout, auto detect 404 pages func won't work.(But you can "
                                      "still scan)")
            self.output.print_warning("You should consider use -t <NUM> to extend timeout.")
            return
        _404_body = await _404_res.read()
        # 记录404
        self._404_page = Page(status=_404_res.status,
                              body=_404_body[:2 * 1024 * 1024],
                              headers=_404_res.headers,
                              charset=_404_res.charset,
                              content_type=_404_res.content_type,
                              content_length=_404_res.content_length if _404_res.content_length is not None else len(
                                  _404_body))

    # 检查404
    async def is_404_pages(self, _res: aiohttp.ClientResponse):
        if _res.status == 404:
            return True
        if _res.headers.get('content-type') is None or _res.headers.get('content-type').find("text/html") == -1:
            return False
        _body = await _res.read()
        compare_page = Page(status=_res.status,
                            body=_body,
                            headers=_res.headers,
                            charset=_res.charset,
                            content_type=_res.content_type,
                            content_length=_res.content_length if _res.content_length is not None else len(
                                _body))
        ratio = min(self._404_page.content_length, compare_page.content_length) / max(self._404_page.content_length,
                                                                                      compare_page.content_length)
        if ratio < 0.9:
            return False
        if difflib.SequenceMatcher(None, self._404_page.get_title(), compare_page.get_title()).ratio() > 0.6:
            return True
        return False

    # 解析网页
    async def __page_url_collect(self, response=None, init_page_flag=False, only_check_404=False):
        if init_page_flag:
            url = self.__check_href(response)
            if url is None:
                return
            self.tree.add(url)
            node = self.tree.get_node(url)
            try:
                response = (await self.get_response(response, timeout=self.timeout))
            except Exception as e:
                self.output.print_error("ERR: " + str(e))
                self.output.print_error("Init first page failed. Check url is correct.")
                exit(0)
            node.set_status(response.status)
            node.set_access(True)

        headers = response.headers

        if headers.get('content-type') is None or headers.get('content-type').find("text/html") == -1:
            return

        charset = re.findall("charset=(.*?)$", headers.get('content-type'))
        if len(charset) == 1:
            charset = charset[0]
        else:
            charset = None
        html = await response.read()
        not_found = self.__parse_results(html, str(response.url), charset=charset, only_check_404=only_check_404)
        if not_found:
            return True
        if only_check_404:
            return False
        for node in self.tree.enum_tree():
            if not node.is_access():
                node.set_access()
                self.queue.put_nowait(node.get_full_path())

    # 根据后缀读取爆破字典
    def __init_fuzz_list(self, url_list):
        if isinstance(url_list, str):
            dir_file = open(url_list)
            for dirs in dir_file.readlines():
                self.urls.append(dirs[:-1].replace("%EXT%", self.args.get_args("extend")))

        elif isinstance(url_list, list):
            self.urls = url_list
        else:
            raise ParameterTypeError("Fuzz_list is required to be str or list , But a %s was given." % type(url_list))
        self.fuzz_num = len(self.urls)

    # 将获取到的url加入Tree
    def __parse_results(self, html, __url, charset=None, only_check_404=False):
        try:
            soup = BeautifulSoup(html, 'html.parser', from_encoding=charset)
            if self.args.get_args("not_found") is not None:
                regexp = re.compile(self.args.get_args("not_found"))
                if soup.find(text=regexp):
                    return True
            if only_check_404:
                return False
            href_list = soup.find_all('a')
            action_list = soup.find_all('form')
            if self.args.get_args("static"):
                src_list = soup.find_all('img')
                src_list.extend(soup.find_all('script'))

        except Exception as e:
            raise Exception(e)

        # Collect href of tag <a>
        for href in map(lambda tag: tag.get('href'), href_list):
            try:
                self.tree.add(self.__check_href(href, __url))
            except Exception as e:
                pass
        # Collect href of tag <from>
        for href in map(lambda tag: tag.get('action'), action_list):
            try:
                self.tree.add(self.__check_href(href, __url))
            except Exception as e:
                pass

        # Collect image URLs
        if self.args.get_args("static"):
            for href in map(lambda tag: tag.get('src'), src_list):
                try:
                    self.tree.add(self.__check_href(href, __url))
                except Exception:
                    pass

    # 检查是否是外部链接，不属于该网站
    def __check_href(self, href, __url=None):
        if href is None:
            return
        parse = urlparse(href)

        if __url is None or parse.netloc == self.netloc:
            return parse.path

        if parse.scheme == "":
            return urlparse(urljoin(__url, href)).path

        return None

    async def get_response(self, url, allow_redirects=True, timeout=12):
        headers = self.header.copy()
        headers['User-agent'] = random.choice(self.UA)
        return await self.session.get(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)

    # 保证当其余协程未完成但队列为空时协程继续，
    async def co_routine(self):
        hang_up = False

        while self.alive_routine:
            if not self.queue.empty():
                url = await self.queue.get()
                if hang_up:
                    self.alive_routine += 1
                    hang_up = False
            else:
                if not hang_up:
                    self.alive_routine -= 1
                    hang_up = True
                await asyncio.sleep(0.5)
                continue

            if not self.map_finish:
                full_url = urljoin(self.prefix, url)
            else:
                full_url = urljoin(self.fuzz_prefix, url)

            self.last_proceed_url = url
            if not self.map_finish:
                self.output.print_lastLine("Processing: %s" % url)
            else:
                self.fuzz_progress += 1
                self.output.print_progress((self.fuzz_progress / self.fuzz_num) * 100, url)
            try:

                res = await self.get_response(full_url,
                                              allow_redirects=(self.args.get_args("no_re") is False),
                                              timeout=self.timeout)

                is_404 = False
                if self._404_page is not None:
                    is_404 = await  self.is_404_pages(res)
                status = 404 if is_404 else res.status

                if status != 404:
                    if status == 200:
                        not_found_flag = False
                        if not self.map_finish:
                            not_found_flag = await self.__page_url_collect(res)
                        elif self.fuzz and self.not_found_flag:
                            not_found_flag = await self.__page_url_collect(res, only_check_404=True)
                        if not_found_flag:
                            continue

                    if not self.map_finish or status == 200:
                        try:
                            if self.map_finish:
                                url = urljoin(self.fuzz_base, url)
                            self.tree.add(url)
                            node = self.tree.get_node(url)
                            node.set_status(status)
                            node.set_access(True)

                        except KeyError:
                            pass
                        except Exception as e:
                            self.output.print_error(url)
                            raise Exception(e)

                # 发成重定向
                if len(res.history) != 0 and (status != 404 or self.more_detail):
                    self.output.print_history(res, url)

                elif status != 404:
                    if 400 <= status <= 403:
                        if self.detail:
                            self.output.print_info("{0} - {1}".format(status, Fore.GREEN + url + Style.RESET_ALL))
                    else:
                        self.output.print_info("{0} - {1}".format(status, Fore.GREEN + url + Style.RESET_ALL))

                if not self.map_finish:
                    self.output.print_lastLine("Processing: %s" % self.last_proceed_url)
                else:
                    self.output.print_progress((self.fuzz_progress / self.fuzz_num) * 100, self.last_proceed_url)

            except aiohttp.client_exceptions.ClientConnectionError as e:
                if self.more_detail:
                    self.output.print_error("RST - :%s" % (
                            Fore.BLUE + url + Style.RESET_ALL))

            except asyncio.TimeoutError:
                if self.detail:
                    self.output.print_warning("OUT - %s" % url)
                self.time_out_times += 1

            except aiohttp.client_exceptions.InvalidURL as e:
                if self.detail:
                    self.output.print_warning("ERR - %s" % url)
                if self.more_detail:
                    self.output.print_warning("RES : aiohttp.client_exceptions.InvalidURL")
            except Exception as e:
                if self.more_detail:
                    self.output.print_error(
                        "An unknown error occurred when Requesting url:%s" % (
                                Fore.BLUE + full_url + Style.RESET_ALL))
                    self.output.print_error("Error:%s" % e)
                    raise e
                self.alive_routine -= 1
                raise Exception(e)

    def __start_co_routine(self):
        self.alive_routine = self.max_threads
        tasks = [self.co_routine() for i in range(self.max_threads)]
        self.loop.run_until_complete(asyncio.wait(tasks))

    def __start(self):
        try:
            self.__init__404_page()
        except Exception as e:
            self.output.print_error("Something wrong when init 404 page")
            if self.detail or self.more_detail:
                self.output.print_error("ERR: " + str(e))
            self.output.print_warning("Auto detect 404 func will be close. But you can still scan.")

        if self.args.get_args("map"):
            self.output.print_info("Start Mapping...")
            self.__init__crawler_list()
            self.__start_co_routine()

        self.map_finish = True
        if self.args.get_args("fuzz"):
            self.output.print_info("Start Fuzzing...")
            for url in self.urls:
                self.queue.put_nowait(url)
            self.__start_co_routine()

    def start(self):

        self.start_time = time.time()
        self.output.print_info("Start: %s" % time.strftime("%H:%M:%S"))

        try:
            self.__start()

        except KeyboardInterrupt:
            self.output.print_error("Aborted by user!")

        except Exception as e:
            self.output.print_error("Fatal error occurs!")
            # self.output.print_error("Error: %s" % e)
            raise e

        if self.time_out_times >= 5:
            self.output.print_warning(
                "There are too many Time-out queries, You can make it better by reducing the num of co-routine. ")

        self.output.print_info("End: %s" % time.strftime("%H:%M:%S"))
        self.report()

    def report(self):
        # 生成扫描报告
        end = time.time()
        redirect = False

        # 如果页面比较大
        if self.tree.num_of_nodes > 100:
            self.output.print_warning(
                "It seems web site map is too large to display at the terminal(%d nodes!)." % (
                    self.tree.num_of_nodes))
            self.output.print_warning("Would you want to redirect the output to file? [no/YES]: ", nowrap=True)
            redirect = input()
            if redirect in ['NO', "no", "N", "n"]:
                redirect = False
            else:
                redirect = True

        if redirect:

            file_name = self.netloc.replace(":", "_") + ".txt"
            _output_dir = self.args.get_args("output")
            if _output_dir:
                if not os.path.exists(_output_dir):
                    os.makedirs(_output_dir)
            else:
                _output_dir = self.work_path

            output_file_path = os.path.join(_output_dir, file_name)

            file = open(output_file_path, "w+", encoding="utf-8")
            self.output.redirect_to_file(file)  # Switch sys.out to file

            # Report details
            print("\n# ====================================== Report =======================================\n")
            print("URL: " + self.init_url)
            print("Host: " + self.netloc)
            print("Scan time: {}".format(time.strftime("%Y/%m/%d %H:%M:%S")))
            print("Cost: {:.2f} s".format(end - self.start_time))
            # Web map
            if not self.args.get_args("no_map"):
                print("\n# =================================== Web site map ====================================\n"
                      "# You can use `--no-map` to not display it in report \n"
                      "# =====================================================================================\n")
                self.tree.print_tree()
            # Site urls
            if not self.args.get_args("--no-urls"):
                print("\n# =================================== Web site urls ===================================\n"
                      "# Record all url response without status code 4xx or 5xx \n"
                      "# You can use `--no-urls` to not display it in report \n"
                      "# =====================================================================================\n")
                self.tree.print_all_path(_filter=lambda x: x.status < 400)
            self.output.redirect_to_sys()  # Switch sys.out to terminal

            self.output.print_info(
                "Web site map redirect into " + Fore.LIGHTMAGENTA_EX + file_name + Style.RESET_ALL)
            self.output.print_info("Path: " + Fore.LIGHTMAGENTA_EX + _output_dir + Style.RESET_ALL)
            file.close()

        else:
            # Print tree
            self.output.new_line("\n" + Fore.LIGHTYELLOW_EX + "=" * self.output.terminal_size + Style.RESET_ALL)
            self.output.new_line(Fore.LIGHTYELLOW_EX + "Web site map:" + Style.RESET_ALL)
            self.print_tree()
            self.output.new_line("\n" + Fore.LIGHTYELLOW_EX + "=" * self.output.terminal_size + Style.RESET_ALL)

        self.output.print_info("Scan finished. Cost %.2f s." % (end - self.start_time))

    async def sess_close(self):
        await self.session.close()

    # 打印网站tree结构
    def print_tree(self):
        for node in self.tree.enum_tree():
            print(Fore.WHITE + " │   " * node.get_depth() + " +-- " + Style.RESET_ALL, end="")
            status = node.get_status()

            if status == 200:
                print(Fore.YELLOW + node.get_name() + Style.RESET_ALL, end=" ")

            elif status == 404:
                print(Fore.RED + node.get_name() + Style.RESET_ALL, end=" ")

            elif status in [301, 302, 307]:
                print(Fore.GREEN + node.get_name() + Style.RESET_ALL, end=" ")
            else:
                print(Fore.LIGHTMAGENTA_EX + node.get_name() + Style.RESET_ALL, end=" ")

            print(Fore.CYAN + str(status) + Style.RESET_ALL)

    # 关闭aiohttp连接
    def __del__(self):
        if self.loop:
            self.loop.run_until_complete(self.sess_close())
        try:
            if not self.session.closed:
                if self.session._connector_owner:
                    self.session._connector.close()
                self.session._connector = None
            if not self.loop.is_closed():
                self.loop.close()
        except Exception:
            if self.output:
                self.output.print_error("Session was not closed or didn't exit.")
            raise SessionError("Session was not closed")

    @staticmethod
    def getrandhex(length: int) -> str:
        return "%x" % getrandbits(4 * length)


if __name__ == '__main__':
    pass
