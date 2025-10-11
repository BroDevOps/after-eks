1. Create eks-ng-role
2. Create PEM key
3. Create AWS key for ebs
4. Pick a subnet
5. Create SG for EKS-Nodes or use existing

----


for cluster autoscaler
```bash
# find out already isntalled cluster autoscaler components
configure aws profile first
create source venv for python
python3 install_cluster_autoscaler.py
python3 ng.py
kubectl get all -n kube-system | grep -i "autoscaler"
```
<img width="1122" height="788" alt="image" src="https://github.com/user-attachments/assets/6ec78290-ea45-46b0-99bc-057b7c0d33c0" />
