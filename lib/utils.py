import base64
import logging
from concurrent.futures import ThreadPoolExecutor, wait

from impacket import ntlm
from impacket.dcerpc.v5 import transport

from certipy.lib.target import Target
from impacket.dcerpc.v5.rpcrt import MSRPCHeader

logger = logging.getLogger('utils')


def get_all_dcs(target: Target):
    target_domain = target.domain
    super_resolver = target.resolver.resolver

    if not all([target_domain, super_resolver.nameservers]):
        logger.error('you must specify domain name and a nameserver')
        return []
    try:
        aws = target.resolver.resolver.resolve(target.domain)
        logger.debug(f'got dc ips: {list(aws)}')
        return [str(aw) for aw in list(aws)]
    except Exception as e:
        logger.error(f'some error happened resolving domain name: {e}')
        return []


def target_validator(target: Target, must_specify_attrs: list):
    """
    @target_validator 用于验证参数是否满足必要条件，must_specify_attrs为一个嵌套数组，该数组内允许str、
    tuple两种数据类型，原数组内所有属性满足条件为且，若存在嵌套数组，则满足条件为或，如：
    ['domain', 'username'] 含义为target需要存在domain AND username
    ['domain', 'username', ('password', 'hashes')] 表示
    target中需要存在 domain AND username AND (password OR hashes)
    """
    for must_specify_attr in must_specify_attrs:
        try:
            if isinstance(must_specify_attr, str):
                attr = getattr(target, must_specify_attr)
                if not attr:
                    logger.error(f'parameter {must_specify_attr} not specified.')
                    return False
            if isinstance(must_specify_attr, tuple):
                if not any([getattr(target, must_attr) for must_attr in must_specify_attr]):
                    logger.error(f'one of the following parameters must specified [{", ".join(must_specify_attr)}] .')
        except AttributeError as e:
            logger.error(f'get attribute error: {e}')
            return False

    return True


def multi_run(fn, targets, max_worker=10):
    with ThreadPoolExecutor(max_workers=max_worker) as pool:
        logger.info(f'{len(targets)} to run with max worker {max_worker}')
        fs = [pool.submit(fn, target) for target in targets]
        wait(fs)


def ntlm_info(target_ip, method='rpc'):
    available_method = {'smb': f'ncacn_np:{target_ip}[\\PIPE\\netlogon]',
                        'rpc': f'ncacn_ip_tcp:{target_ip}[135]',
                        'ldap': f''}
    target_info = {ntlm.NTLMSSP_AV_DNS_HOSTNAME: '',
                   ntlm.NTLMSSP_AV_DNS_DOMAINNAME: '',
                   ntlm.NTLMSSP_AV_DNS_TREENAME: '',
                   ntlm.NTLMSSP_AV_HOSTNAME: ''}

    bind_data = base64.b64decode('BQALAxAAAABwACAAAQAAALgQuBAAAAAAAQAAAAAAAQAIg6/hH13JEZGkCAArFKD6AwAAAARdiIrr'
                                 'HMkRn+gIACsQSGACAAAACgIAAAAAAABOVExNU1NQAAEAAAAFAoigAAAAAAAAAAAAAAAAAAAAAA==')
    if method not in available_method:
        logger.error(f'available methods: {available_method}')
    if method != 'ldap':
        c = transport.DCERPCTransportFactory(available_method.get(method))
        c.connect()
        c.send(bind_data)
        s = c.recv()
        if s:
            logger.debug(s)
            resp = MSRPCHeader(s)
            auth_data = resp['auth_data']
            challenge_msg = ntlm.NTLMAuthChallenge(auth_data)
            av_pairs = ntlm.AV_PAIRS(challenge_msg['TargetInfoFields'])
            for k in target_info:
                _, av_data = av_pairs[k]
                target_info[k] = av_data.decode('utf-16')
            logger.debug(target_info)
        else:
            logger.error(f'no data received')

    else:
        pass

    return target_info


if __name__ == '__main__':
    t = Target.create(dc_ip='192.168.31.110',
                      domain='jd.local',
                      password='1234')

    # target_validator(t, ['dc_ip', 'domain', ('hashes', 'password')])
    ntlm_info('192.168.31.110', 'smb')
    # dcpis = get_all_dcs(t)
    # print(dcpis)
