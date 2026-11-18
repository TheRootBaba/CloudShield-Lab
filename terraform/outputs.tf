output "cloudtrail_name" {
  description = "Name of the multi-region CloudTrail trail."
  value       = aws_cloudtrail.security.name
}

output "cloudtrail_bucket" {
  description = "Private encrypted bucket receiving CloudTrail events."
  value       = aws_s3_bucket.cloudtrail.id
}
