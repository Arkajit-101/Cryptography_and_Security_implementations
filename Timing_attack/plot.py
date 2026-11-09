"""Plot real CPU cycles vs operation-count from traces.csv.
Left : raw scatter (every decryption).
Right: average cycles per operation-count bucket -- cuts through CPU noise and
       shows the monotonic trend = 'more secret-dependent work -> more time'."""
import csv, os, matplotlib
matplotlib.use("TkAgg") if os.environ.get("DISPLAY") else matplotlib.use("Agg")
import matplotlib.pyplot as plt
cyc=[]; op=[]
for r in csv.DictReader(open("traces.csv")):
    cyc.append(float(r["cycles"])); op.append(float(r["opcount"]))
n=len(cyc); mc=sum(cyc)/n; mo=sum(op)/n
cov=sum((cyc[i]-mc)*(op[i]-mo) for i in range(n))
corr=cov/((sum((x-mc)**2 for x in cyc)*sum((x-mo)**2 for x in op))**.5)

# bucket cycles by opcount, take the mean (and std-error) per bucket
from collections import defaultdict
import math
buck=defaultdict(list)
for o,c in zip(op,cyc): buck[int(o)].append(c)
xs=sorted(k for k,v in buck.items() if len(v)>=3)
means=[sum(buck[k])/len(buck[k]) for k in xs]
errs=[ (lambda v,m: (sum((x-m)**2 for x in v)/len(v))**.5/len(v)**.5)(buck[k],sum(buck[k])/len(buck[k])) for k in xs]

fig,ax=plt.subplots(1,2,figsize=(13,5))
ax[0].scatter(op,cyc,s=8,alpha=0.30,color="#6c5ce7")
ax[0].set_xlabel("operation count (secret-dependent work)")
ax[0].set_ylabel("real CPU cycles")
ax[0].set_title(f"every decryption   (r = {corr:+.3f})")
ax[1].errorbar(xs,means,yerr=errs,fmt="o-",color="#e17055",ecolor="#b2bec3",
               capsize=3,markersize=4,linewidth=1.5)
ax[1].set_xlabel("operation count (secret-dependent work)")
ax[1].set_ylabel("MEAN CPU cycles")
ax[1].set_title("average time per work-level  (the leak, de-noised)")
fig.suptitle("Timing leak: decryption time tracks the secret-dependent work",
             fontweight="bold")
fig.tight_layout()
fig.savefig("timing_plot.png",dpi=130)
print(f"correlation(cycles, work) = {corr:+.3f}   |  saved timing_plot.png")
try: plt.show()
except Exception: pass
