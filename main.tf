resource "random_id" "cluster_name" {
  byte_length = 6
}

## Get your workstation external IPv4 address:
data "http" "workstation-external-ip" {
  url   = "http://ipv4.icanhazip.com"
}

locals {
  workstation-external-cidr = "${chomp(data.http.workstation-external-ip.body)}/32"
}

data "aws_availability_zones" "available" {
}

data "aws_region" "current" {
}

data "aws_ami" "eks-worker" {
  filter {
    name   = "name"
    values = ["amazon-eks-node-${aws_eks_cluster.cluster.version}-v*"]
  }

  most_recent = true
  owners      = ["602401143452"] # Amazon EKS AMI Account ID
}


# VPC
resource "aws_vpc" "main" {
  cidr_block = var.aws_cidr_block

  tags = {
    Name = "${var.cluster_name}"
    Project   = "k8s"
    ManagedBy = "terraform"
    "kubernetes.io/cluster/${var.cluster_name}-${random_id.cluster_name.hex}" = "shared"
  }
}

resource "aws_subnet" "workers" {
  count = var.worker_subnets
  
  availability_zone = data.aws_availability_zones.available.names[count.index]
  cidr_block        = cidrsubnet(cidrsubnet(var.aws_cidr_block, 0, 0), var.worker_subnets, count.index)
  #cidrsubnet(var.aws_cidr_block, 8, count.index)
  vpc_id            = aws_vpc.main.id

  tags =  {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}-workers-${data.aws_availability_zones.available.names[count.index]}"
    Project   = "k8s"
    ManagedBy = "terraform"
    "kubernetes.io/cluster/${var.cluster_name}-${random_id.cluster_name.hex}" = "shared"
  }
}

resource "aws_subnet" "private" {
  for_each = var.subnets

  # availability_zone = data.aws_availability_zones.available.names[count.index]
  cidr_block        = each.value.cidr
  #cidrsubnet(var.aws_cidr_block, 8, count.index)
  vpc_id            = aws_vpc.main.id

  tags =  merge({
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}-${each.key}"
    Project   = "k8s"
    ManagedBy = "terraform"
    "kubernetes.io/cluster/${var.cluster_name}-${random_id.cluster_name.hex}" = "shared"
    "infoblox.com/subnet/use" = "${each.key}"
  }, [for o in coalesce(each.value.tags, []) : { o.tag :  o.value}]...)
}


resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}

resource "aws_route_table_association" "workers" {
  count = length(aws_subnet.workers)

  subnet_id      = aws_subnet.workers.*.id[count.index]
  route_table_id = aws_route_table.rt.id
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id = values(aws_subnet.private)[count.index].id
  #values(aws_subnet.private)[count.index].id
  route_table_id = aws_route_table.rt.id
}


# Master IAM
resource "aws_iam_role" "cluster" {
  name  = "${var.cluster_name}-${random_id.cluster_name.hex}"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role_policy_attachment" "cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "cluster-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.cluster.name
}

# Master Security Group
resource "aws_security_group" "cluster" {
  name        = "${var.cluster_name}-${random_id.cluster_name.hex}"
  description = "Cluster communication with worker nodes"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}-cluster"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}

# OPTIONAL: Allow inbound traffic from your local workstation external IP
#           to the Kubernetes. See data section at the beginning of the
#           AWS section.
resource "aws_security_group_rule" "cluster-ingress-workstation-https" {
  cidr_blocks       = [local.workstation-external-cidr]
  description       = "Allow workstation to communicate with the cluster API Server"
  from_port         = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.cluster.id
  to_port           = 443
  type              = "ingress"
}


# EKS Master
resource "aws_eks_cluster" "cluster" {
  name     = "${var.cluster_name}-${random_id.cluster_name.hex}"
  role_arn = aws_iam_role.cluster.arn
  #version = var.aws_eks_version

  vpc_config {
    security_group_ids = [aws_security_group.cluster.id]
    subnet_ids         = flatten(aws_subnet.workers[*].id)
  }

  depends_on = [
    aws_iam_role_policy_attachment.cluster-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.cluster-AmazonEKSServicePolicy,
  ]
  
  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}


# EKS Worker IAM
resource "aws_iam_role" "node" {
  name = "${var.cluster_name}-${random_id.cluster_name.hex}-node"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}-node"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role_policy_attachment" "node-AmazonEKSWorkerNodePolicy" {
 policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node-AmazonS3ReadOnlyAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
  role       = aws_iam_role.node.name
}

resource "aws_iam_instance_profile" "node" {
  name  = "${var.cluster_name}-${random_id.cluster_name.hex}"
  role  = aws_iam_role.node.name

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}


# EKS Worker Security Groups
resource "aws_security_group" "node" {
  name        = "${var.cluster_name}-${random_id.cluster_name.hex}-node"
  description = "Security group for all nodes in the cluster"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = tomap({
    "kubernetes.io/cluster/${var.cluster_name}-${random_id.cluster_name.hex}" = "owned"
  })
}

resource "aws_security_group_rule" "demo-node-ingress-self" {
  description              = "Allow node to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.node.id
  source_security_group_id = aws_security_group.node.id
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "demo-node-ingress-cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = aws_security_group.node.id
  source_security_group_id = aws_security_group.cluster.id
  to_port                  = 65535
  type                     = "ingress"
}


# EKS Master <--> Worker Security Group
resource "aws_security_group_rule" "cluster-ingress-node-https" {
  description              = "Allow pods to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.cluster.id
  source_security_group_id = aws_security_group.node.id
  to_port                  = 443
  type                     = "ingress"
}


# EKS Worker Nodes AutoScalingGroup

# EKS currently documents this required userdata for EKS worker nodes to
# properly configure Kubernetes applications on the EC2 instance.
# We implement a Terraform local here to simplify Base64 encoding this
# information into the AutoScaling Launch Configuration.
# More information: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
locals {
  demo-node-userdata = <<USERDATA
#!/bin/bash
set -o xtrace
/etc/eks/bootstrap.sh --apiserver-endpoint '${aws_eks_cluster.cluster.endpoint}' --b64-cluster-ca '${aws_eks_cluster.cluster.certificate_authority.0.data}' '${var.cluster_name}-${random_id.cluster_name.hex}'
USERDATA
}

resource "aws_launch_configuration" "lc" {
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.node.name
  image_id                    = data.aws_ami.eks-worker.id
  instance_type               = var.aws_instance_type
  name_prefix                 = var.cluster_name
  security_groups             = [aws_security_group.node.id]
  user_data_base64            = base64encode(local.demo-node-userdata)
}

resource "aws_autoscaling_group" "asg" {
  desired_capacity     = var.eks_nodes
  launch_configuration = aws_launch_configuration.lc.id
  max_size             = var.eks_max_nodes
  min_size             = var.eks_min_nodes
  name                 = var.cluster_name
  vpc_zone_identifier  = aws_subnet.workers[*].id

  tag {
    key                 = "Name"
    value               = var.cluster_name
    propagate_at_launch = true
  }

  tag {
    key                 = "Project"
    value               = "k8s"
    propagate_at_launch = true
  }

  tag {
    key                 = "ManagedBy"
    value               = "terraform"
    propagate_at_launch = true
  }
  tag {
    key                 = "kubernetes.io/cluster/${var.cluster_name}-${random_id.cluster_name.hex}"
    value               = "owned"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# EKS Join Worker Nodes
# EKS kubeconf
locals {
  config_map_aws_auth = <<CONFIGMAPAWSAUTH
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: ${aws_iam_role.node.arn}
      username: system:node:{{EC2PrivateDNSName}}
      groups:
        - system:bootstrappers
        - system:nodes
CONFIGMAPAWSAUTH

  kubeconfig = <<KUBECONFIG
apiVersion: v1
clusters:
- cluster:
    server: ${aws_eks_cluster.cluster.endpoint}
    certificate-authority-data: ${aws_eks_cluster.cluster.certificate_authority.0.data}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: aws
  name: aws
current-context: aws
kind: Config
preferences: {}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws-iam-authenticator
      args:
        - "token"
        - "-i"
        - "${var.cluster_name}-${random_id.cluster_name.hex}"
KUBECONFIG
}

resource "local_file" "kubeconfig" {
  content  = local.kubeconfig
  filename = var.kubeconfig

  depends_on = [aws_eks_cluster.cluster]
}

resource "local_file" "eks_config_map_aws_auth" {
  content  = local.config_map_aws_auth
  filename = "${path.module}/aws_config_map_aws_auth"

  depends_on = [local_file.kubeconfig]
}

resource "null_resource" "aws_iam_authenticator" {
  provisioner "local-exec" {
    command = <<EOF
if [ "$(uname -s)" == "Darwin" ]; 
  then curl -o aws-iam-authenticator https://amazon-eks.s3-us-west-2.amazonaws.com/1.13.7/2019-06-11/bin/darwin/amd64/aws-iam-authenticator; 
else curl -o aws-iam-authenticator https://amazon-eks.s3-us-west-2.amazonaws.com/1.12.7/2019-03-27/bin/linux/amd64/aws-iam-authenticator; 
fi; 
chmod +x ./aws-iam-authenticator; 
mkdir -p $HOME/bin && 
cp ./aws-iam-authenticator $HOME/bin/aws-iam-authenticator && 
export PATH=$HOME/bin:$PATH
EOF
  }

  depends_on = [local_file.eks_config_map_aws_auth]
}

resource "null_resource" "apply_kube_configmap" {
  provisioner "local-exec" {
    command = "kubectl apply -f ${path.module}/aws_config_map_aws_auth"
    environment = {
      KUBECONFIG = local_file.kubeconfig.filename
    }
  }

  depends_on = [null_resource.aws_iam_authenticator]
}

resource "aws_iam_role" "crossplane" {
  name = "${var.cluster_name}-${random_id.cluster_name.hex}-crossplane"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}-crossplane"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}

resource "aws_iam_policy" "crossplane" {
  name = "${var.cluster_name}-${random_id.cluster_name.hex}-crossplane"

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}-crossplane"
    Project   = "k8s"
    ManagedBy = "terraform"
  }

  # TODO: reduce to only the required permissions
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["*"],
    "Resource": "*"
  }]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "crossplane" {
  policy_arn = aws_iam_policy.crossplane.arn
  role       = aws_iam_role.crossplane.name
}

resource "aws_iam_role" "db-controller" {
  name = "${var.cluster_name}-${random_id.cluster_name.hex}-db-controller"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY

  tags = {
    "Name" = "${var.cluster_name}-${random_id.cluster_name.hex}-db-controller"
    Project   = "k8s"
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role_policy_attachment" "db-controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
  role       = aws_iam_role.db-controller.name
}
