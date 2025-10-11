1. Create eks-ng-role
2. Create PEM key
3. Create AWS key for ebs
4. Pick a subnet
5. Create SG for EKS-Nodes or use existing

----


for cluster autoscaler
```bash
# find out already isntalled cluster autoscaler components 
kubectl get all -n kube-system | grep -i "autoscaler"
```