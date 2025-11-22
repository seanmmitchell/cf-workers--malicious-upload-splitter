interface Env {
	MUS: R2Bucket;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (!env.MUS) {
			return new Response('Internal Server Error: R2 Bucket not Available', { status: 500 });
		}

		const url = new URL(request.url);
		const path = url.pathname;


		if (path === '/') {
			return handleUpload(request, env.MUS);
		} else if (path === '/upload') {
			return handleUpload(request, env.MUS);
		} else if (path.startsWith('/file')) {
			return handleR2Request(request, env.MUS);
		} else {
			return new Response('Not found', { status: 404 });
		}
	},
};


async function handleUpload(request: Request, bucket: R2Bucket): Promise<Response> {
	try {
		if (request.method !== 'POST') {
			return new Response('Method not allowed', { status: 405 });
		}

		const formData = await request.formData();
		const fileData2 = formData.getAll('file');

		if (!fileData2.length) {
			return new Response('No files found in the request', { status: 400 });
		}

		// Attempt to Upload Files Individually
		type fileData = {
			Success: boolean
			Filename: string
			Reason: string
		}
		type uploadWAFAPIResponse = {
			Success: string // false, true, or partial
			Files: fileData[]
		}
		let uploadFailed = false
		let uploadResults: fileData[] = []

		const uploadPromises = fileData2.map(async (file) => {
			if (file instanceof File) {
				const uploadFormData = new FormData();
				uploadFormData.append('file', file);

				try {
					let newHeaders = new Headers(request.headers)
					newHeaders.set(
						"User-Agent", "MUS Forwarder",
					)
					newHeaders.delete(
						"Content-Type"
					)

					console.log(`\t>> ${file.name} -- checking....`)
					const response = await fetch('https://bfa.srnd.net/upload?fn=' + encodeURI(file.name), {
						method: 'POST',
						headers: newHeaders,
						body: uploadFormData,
					});


					if (!response.ok) {
						// If there is an error, lets see if we can parse it as a JSON WAF response.
						type cfWAFResponse = {
							Success: boolean
							Message: string
						}
						var responseText = await response.text()
						try {
							let x = JSON.parse(responseText) as cfWAFResponse
							console.log(`\t>> ${file.name} -- parsed....`)

							if (x.Success == true && x.Message == "Malicious") {
								// Malicious Upload Prevented
								console.log(`${file.name} -- file is malicious`)
								uploadFailed = true
								let finalRes: fileData = {
									Success: true,
									Filename: file.name,
									Reason: "Malicious"
								}
								uploadResults.push(finalRes)

								const promises = fileData2.map((file) => {
									if (file instanceof File) {
										const filename = file.name;
										return bucket.put(filename, file.stream());
									} else {
										throw new Error('Invalid file type');
									}
								});

								await Promise.all(promises);
							}
							else if (x.Success == false && x.Message == "Failed") {
								// Failed Upload Scan 
								console.log(`${file.name} -- failed upload scan`)
								uploadFailed = true
								let finalRes: fileData = {
									Success: false,
									Filename: file.name,
									Reason: "Failed"
								}
								uploadResults.push(finalRes)

								const promises = fileData2.map((file) => {
									if (file instanceof File) {
										const filename = file.name;
										return bucket.put(filename, file.stream());
									} else {
										throw new Error('Invalid file type');
									}
								});

								await Promise.all(promises);
							}
							else if (x.Success == true && x.Message == "Scanned") {
								// Upload Scanned & Clean 
								console.log(`${file.name} -- scanned and clean`)
								let finalRes: fileData = {
									Success: false,
									Filename: file.name,
									Reason: "Failed"
								}
								uploadResults.push(finalRes)
								return
							}
							else {
								// Unknown error response in cfWAFResponse format.
								uploadFailed = true
								let finalRes: fileData = {
									Success: false,
									Filename: file.name,
									Reason: x.Message
								}

								console.log(`${file.name} -- unknown state`)
								console.warn(`errResponseStatus | ${response.status} | errResponseMessage | ${response.statusText} | errResponseBody | ${responseText}`);

								uploadResults.push(finalRes)
								const promises = fileData2.map((file) => {
									if (file instanceof File) {
										const filename = file.name;
										return bucket.put(filename, file.stream());
									} else {
										throw new Error('Invalid file type');
									}
								});

								await Promise.all(promises);
								return
							}
						} catch (error) {
							// We can canot parse it as a JSON WAF Message, so it must be coming from something else. Likely origin.
							console.log(`${file.name} -- upload failed / unexpected response`)
							console.warn(`errResponseStatus | ${response.status} | errResponseMessage | ${response.statusText} | errResponseBody | ${responseText}`);

							uploadFailed = true
							let finalRes: fileData = {
								Success: false,
								Filename: file.name,
								Reason: "unknown error"
							}
							uploadResults.push(finalRes)
						}
					} else {
						let finalRes: fileData = {
							Success: true,
							Filename: file.name,
							Reason: "Scanned"
						}
						uploadResults.push(finalRes)
					}
				} catch (error) {
					if (error instanceof Error) {
						console.error(`Failed to upload ${file.name} to bfa.srnd.net/upload | <> | errorMessage | ${error.message}`);
					} else {
						console.error(`Failed to upload ${file.name} to bfa.srnd.net/upload | <> | errorMessage | ${error}`);
					}

				}
			}
		});

		await Promise.all(uploadPromises);

		let finRes: uploadWAFAPIResponse = {
			Success: "false",
			Files: uploadResults
		}

		if (uploadFailed) {
			finRes.Success = `${!uploadFailed}`
		} else {
			finRes.Success = `true`
		}
		return new Response(JSON.stringify(finRes), { status: 200 });
	} catch (error) {
		if (error instanceof Error) {
			console.error('Error uploading files:', error);
			if (error.message === 'Invalid file type') {
				return new Response('Invalid file type', { status: 400 });
			}
		}
		return new Response('Internal Server Error: Failed to upload files', { status: 500 });
	}
}

async function handleR2Request(request: Request, bucket: R2Bucket): Promise<Response> {
	const url = new URL(request.url);
	const path = url.pathname.replace('/file/', '');

	switch (request.method) {
		case 'GET':
			if (path === '') {
				return listObjects(bucket);
			} else {
				return getObject(bucket, path);
			}
		case 'PUT':
			return putObject(bucket, path, request);
		default:
			return new Response('Method not allowed', { status: 405 });
	}
}

async function listObjects(bucket: R2Bucket): Promise<Response> {
	const objects = await bucket.list();
	return new Response(JSON.stringify(objects.objects), {
		headers: { 'Content-Type': 'application/json' },
	});
}

async function getObject(bucket: R2Bucket, key: string): Promise<Response> {
	const object = await bucket.get(key);
	if (!object) {
		return new Response('Object not found', { status: 404 });
	}
	return new Response(object.body, {
		headers: { 'Content-Type': object.httpMetadata?.contentType || 'application/octet-stream' },
	});
}

async function putObject(bucket: R2Bucket, key: string, request: Request): Promise<Response> {
	await bucket.put(key, request.body);
	return new Response('Object uploaded successfully', { status: 200 });
}