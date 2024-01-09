import subprocess

def get_yafu_pids():

    run_command = "ps -a"
    parse = subprocess.run( run_command, capture_output=True, shell=True, timeout = 10 )
    parse = parse.stdout.decode('utf-8').split("\n")
    parse = [ line.split()[0] for line in parse if "yafu" in line ]
    for idx, line in enumerate( parse ):
        print( idx + 1, line)

    return parse

def renice_pids( pids = []):

    for pid in pids:
        run_command = f"sudo renice -15 -p {pid}"
        parse = subprocess.run( run_command, capture_output=True, shell=True, timeout = 10 )
        parse = parse.stdout.decode('utf-8').split("\n")

pids = get_yafu_pids()
renice_pids( pids )
