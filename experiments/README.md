# Experiments

Experiments contains a helper utility to execute experiments across the backend, auditgen, and auditor.
It assumes that all systems are running on the same machine, as it uses subprocess to spawn the
services and communicates via gRPC over unix socket files.

## Getting started

1. Activate the virtual environment
2. Install the requirements: `make requirements`
3. Go [..](../) and run `make certificates`.
4. Start the infra: `cd ../infra && sudo docker-compose up --build -d`

## Adding and Running Experiments

To define an experiment, create an experiment file in the [experiments/](experiments) subfolder.
See [experiments/basic_transactions.py](experiments/basic_transactions.py) as an example.

To run an experiment, activate your virtual environment, and invoke with
`python3 -m experiments.experiment_name` where the experiment is
named `experiments/experiment_name.py`.

## Code styling

After you make changes, run `make format && make pylint && make typecheck`. It should return without errors.
Then push your code

## Things to pay attention to

- Experiments take on the order of hours to run! The bitcoin node has very low throughput, and the ethereum processing loop is slow.
- Sometimes the experiment runner fails to create the database within the timeout. If this happens, then restart the experiment
- Sometimes the experiment runner fails to die (and kill the other subprocesses) when any of the subprocesses die. If there is any
output in the `stderr.log` file in the `results/experiment_name/timestamp/{auditgen,auditor,backend}/stderr.log` folder, then that
indicates there was an error running the experiment, and it would probably be best to abort the experiment. The only exception to
this rule is when running with `PY_SPY`, and the `auditgen/audit_n/stderr.log` file indicates an error even
when the `auditgen/audit_n/audit.tgz` file exists. If the tarball exists, then the audit was successfully generated.
- Sometimes requests will time out. The timeouts should be sufficiently large, but sometimes they're still not large enough. If a
timeout fails, make sure there aren't zombie processes running. You can check what's running with `htop` or `top` or `ps -e`, and
then kill the process if needed
- When collecting data, make sure the `MANAGE_INFRA` flag is True, and `ENABLE_PY_SPY` flag is False in [utils/runner.py](utils/runner.py).
- When developing, it can be useful to re-use the infra, since it takes ~4 minutes to start everything. You can do this with a
`cd ../infra && docker-compose -f exp.docker-compose.yml up -d`. Make sure that the `MANAGE_INFRA` flag is False in [utils/runner.py](utils/runner.py)
