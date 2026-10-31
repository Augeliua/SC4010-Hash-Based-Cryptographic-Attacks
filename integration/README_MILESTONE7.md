# Milestone 7 files — where they go

Copy the `integration/` folder to the **root of your existing GitHub repository**; do not replace any earlier milestone files.

- `integration/final_check.py`: verifies existing demonstrations and the complete test suite
- `integration/plot_lamport_results.py`: makes a graph from the CSV you generated in Milestone 3
- `integration/PRESENTATION_AND_QA.md`: 8-minute talk outline, claims, likely questions
- `integration/README_MILESTONE7.md`: these instructions

Run in VS Code's terminal from your repository root:

```powershell
python -m integration.final_check
python -m experiments.lamport_experiments
python -m pip install matplotlib
python -m integration.plot_lamport_results
```

The Matplotlib installation is only for the chart. All signing, verification, forgery and automated test code needs only Python standard libraries.

The separate `sample_results/` folder in the ZIP contains the results obtained in the assistant's verification run. They are **reference output**, not a substitute for running experiments on your own checkout. The graph command generates your own `experiments/results/lamport_256bit.png`.
