import logging
from concurrent.futures import ThreadPoolExecutor, wait

from certipy.lib.target import Target

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


if __name__ == '__main__':
    t = Target.create(dc_ip='192.168.31.110',
                      domain='jd.local',
                      password='1234')

    target_validator(t, ['dc_ip', 'domain', ('hashes', 'password')])

    # dcpis = get_all_dcs(t)
    # print(dcpis)
