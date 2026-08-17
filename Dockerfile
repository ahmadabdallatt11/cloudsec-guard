 FROM ubuntu:22.04                                                                                                                                           
                                                                                                                                                              
  RUN apt-get update && apt-get install -y --no-install-recommends \                                                                                          
      ca-certificates \                                                                                                                                       
      && rm -rf /var/lib/apt/lists/*                                                                                                                          
                                                                                                                                                              
  # Create and switch to a non-privileged user                                                                                                                
  RUN useradd --create-home --shell /bin/bash appuser                                                                                                         
  USER appuser                                                                                                                                                
                     