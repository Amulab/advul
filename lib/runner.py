import logging
import sys
from concurrent.futures import ThreadPoolExecutor, wait
from impacket.ntlm import NTLMSSP_AV_DNS_DOMAINNAME

from certipy.lib.target import Target
from .utils import get_all_dcs, target_validator, ntlm_info

logger = logging.getLogger('base')


class Runner:
    def __init__(self, target: Target, required_params=None):
        # 初始化之前进行必要参数检查
        if required_params is None:
            required_params = []
        if not target_validator(target, required_params):
            sys.exit(1)
        self._target = target

    def run(self, target_ip=None):
        """
        虚函数，实现检测逻辑
        """
        logging.error('not implemented')
        raise NotImplementedError()

    def run_multi(self, target_set=None, max_workers=10):
        """
        如果没有指定域控进行攻击那么就利用dns查询所有域控ip，对这些域控进行攻击
        如果指定了域控列表，就对列表内的域控进行攻击
        """
        if target_set is None:
            # 如果没有指定域名，使用ntlm info获取域名
            if not self._target.domain:
                self._target.domain = ntlm_info(self._target.dc_ip)[NTLMSSP_AV_DNS_DOMAINNAME]
            target_set = get_all_dcs(self._target)
        elif isinstance(target_set, str):
            try:
                with open(target_set) as f:
                    target_set = f.readlines()
            except Exception as e:
                logger.error(f'error open file {e}')
                sys.exit(1)
        else:
            target_set = target_set

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            logger.debug(f'{len(target_set)} targets to run with max worker {max_workers}')
            fs = [pool.submit(self.run, target.strip()) for target in target_set]
            wait(fs)

    def exploit(self):
        """
        TODO
        漏洞利用逻辑实现
        """
        pass
