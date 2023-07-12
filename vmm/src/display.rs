use log::info;
use std::sync::mpsc::Sender;
use vulkano::{
    buffer::{BufferUsage, CpuAccessibleBuffer},
    command_buffer::{
        allocator::StandardCommandBufferAllocator, AutoCommandBufferBuilder, CommandBufferUsage,
        CopyBufferToImageInfo, PrimaryCommandBufferAbstract,
    },
    device::{
        physical::PhysicalDeviceType, Device, DeviceCreateInfo, DeviceExtensions, QueueCreateInfo,
        QueueFlags,
    },
    image::ImageUsage,
    instance::{Instance, InstanceCreateInfo},
    memory::allocator::StandardMemoryAllocator,
    swapchain::{
        acquire_next_image, AcquireError, Swapchain, SwapchainCreateInfo, SwapchainCreationError,
        SwapchainPresentInfo,
    },
    sync::{self, FlushError, GpuFuture},
    VulkanLibrary,
};

use vulkano_win::VkSurfaceBuild;
use winit::event_loop::EventLoopBuilder;
use winit::{
    dpi::PhysicalSize,
    event::{Event, WindowEvent},
    event_loop::ControlFlow,
    window::{Window, WindowBuilder},
};

pub fn start(signal: Sender<()>, image_buffer: &mut [u8]) {
    info!("Initializing display.");

    let library = VulkanLibrary::new().expect("no local Vulkan library/DLL");
    let required_extensions = vulkano_win::required_extensions(&library);
    let instance = Instance::new(
        library,
        InstanceCreateInfo {
            enabled_extensions: required_extensions,
            enumerate_portability: true,
            ..Default::default()
        },
    )
    .expect("failed to create instance");

    let mut event_loop_builder = EventLoopBuilder::new();

    let event_loop = event_loop_builder.build();

    let surface = WindowBuilder::new()
        .with_resizable(false)
        .with_inner_size(PhysicalSize {
            width: 1920,
            height: 1080,
        })
        .with_title("vmm")
        // .with_always_on_top(true)
        .with_visible(true)
        // .with_decorations(false)
        .with_transparent(false)
        .build_vk_surface(&event_loop, instance.clone())
        .unwrap();

    let device_extensions = DeviceExtensions {
        khr_swapchain: true,
        ..DeviceExtensions::empty()
    };
    let (physical_device, queue_family_index) = instance
        .enumerate_physical_devices()
        .unwrap()
        .filter(|p| p.supported_extensions().contains(&device_extensions))
        .filter_map(|p| {
            p.queue_family_properties()
                .iter()
                .enumerate()
                .position(|(i, q)| {
                    q.queue_flags.intersects(&QueueFlags {
                        graphics: true,
                        ..Default::default()
                    }) && p.surface_support(i as u32, &surface).unwrap_or(false)
                })
                .map(|i| (p, i as u32))
        })
        .min_by_key(|(p, _)| match p.properties().device_type {
            PhysicalDeviceType::DiscreteGpu => 0,
            PhysicalDeviceType::IntegratedGpu => 1,
            PhysicalDeviceType::VirtualGpu => 2,
            PhysicalDeviceType::Cpu => 3,
            PhysicalDeviceType::Other => 4,
            _ => 5,
        })
        .unwrap();

    info!(
        "Using device: {} (type: {:?})",
        physical_device.properties().device_name,
        physical_device.properties().device_type,
    );

    let (device, mut queues) = Device::new(
        physical_device,
        DeviceCreateInfo {
            enabled_extensions: device_extensions,
            queue_create_infos: vec![QueueCreateInfo {
                queue_family_index,
                ..Default::default()
            }],
            ..Default::default()
        },
    )
    .unwrap();
    let queue = queues.next().unwrap();

    let (mut swapchain, mut images) = {
        let surface_capabilities = device
            .physical_device()
            .surface_capabilities(&surface, Default::default())
            .unwrap();

        if !surface_capabilities.supported_usage_flags.transfer_dst {
            panic!("window surface does not support direct transfer. your graphics driver is bad");
        }

        let image_format = Some(
            device
                .physical_device()
                .surface_formats(&surface, Default::default())
                .unwrap()[0]
                .0,
        );

        info!("swapchain using image format {:?}", image_format);
        let window = surface.object().unwrap().downcast_ref::<Window>().unwrap();

        Swapchain::new(
            device.clone(),
            surface.clone(),
            SwapchainCreateInfo {
                min_image_count: surface_capabilities.min_image_count,
                image_format,
                image_extent: window.inner_size().into(),
                image_usage: ImageUsage {
                    color_attachment: true,
                    transfer_dst: true,
                    ..Default::default()
                },
                composite_alpha: surface_capabilities
                    .supported_composite_alpha
                    .iter()
                    .next()
                    .unwrap(),
                ..Default::default()
            },
        )
        .unwrap()
    };

    let memory_allocator =
        std::sync::Arc::new(StandardMemoryAllocator::new_default(device.clone()));
    let command_buffer_allocator =
        StandardCommandBufferAllocator::new(device.clone(), Default::default());
    let uploads = AutoCommandBufferBuilder::primary(
        &command_buffer_allocator,
        queue.queue_family_index(),
        CommandBufferUsage::OneTimeSubmit,
    )
    .unwrap();

    // Should be possible to use this, but I can't figure it out right now.
    // let buffer_pool = CpuBufferPool::<[u8; 1920 * 1080 * 4]>::upload(memory_allocator.clone());

    // TODO: if the window is resized, the whole thing crashes because the buffer is assumed to be of static size.
    let mut recreate_swapchain = false;
    let mut previous_frame_end = Some(
        uploads
            .build()
            .unwrap()
            .execute(queue.clone())
            .unwrap()
            .boxed(),
    );

    let mut initialized = false;
    // let mut grabbed: bool = false;

    let image_buffer =
        unsafe { core::slice::from_raw_parts_mut(image_buffer.as_mut_ptr(), image_buffer.len()) };

    event_loop.run(move |event, _, control_flow| {
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                info!("display window closed");
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::Focused(true),
                ..
            } => {
                // let window = surface.object().unwrap().downcast_ref::<Window>().unwrap();

                // if !grabbed {
                //     grabbed = true;

                //     window
                //         .set_cursor_grab(CursorGrabMode::Confined)
                //         .expect("failed to capture mouse");

                //     window.set_cursor_visible(false);
                //     window.focus_window();
                //     window
                //         .set_cursor_position(PhysicalPosition {
                //             x: 1920 / 2,
                //             y: 1080 / 2,
                //         })
                //         .unwrap();
                // }
            }

            Event::WindowEvent {
                event: WindowEvent::Focused(false),
                ..
            } => {
                // grabbed = false;
            }
            Event::RedrawEventsCleared => {
                let window = surface.object().unwrap().downcast_ref::<Window>().unwrap();
                let dimensions = window.inner_size();
                if dimensions.width == 0 || dimensions.height == 0 {
                    return;
                }

                previous_frame_end.as_mut().unwrap().cleanup_finished();

                if !initialized {
                    initialized = true;
                    signal.send(()).unwrap();
                }

                if recreate_swapchain {
                    let (new_swapchain, new_images) =
                        match swapchain.recreate(SwapchainCreateInfo {
                            image_extent: dimensions.into(),
                            ..swapchain.create_info()
                        }) {
                            Ok(r) => r,
                            Err(SwapchainCreationError::ImageExtentNotSupported { .. }) => return,
                            Err(e) => panic!("Failed to recreate swapchain: {e:?}"),
                        };

                    images = new_images;

                    swapchain = new_swapchain;
                    // framebuffers =
                    //     window_size_dependent_setup(&new_images, render_pass.clone(), &mut viewport);
                    recreate_swapchain = false;
                }

                let (image_index, suboptimal, acquire_future) =
                    match acquire_next_image(swapchain.clone(), None) {
                        Ok(r) => r,
                        Err(AcquireError::OutOfDate) => {
                            recreate_swapchain = true;
                            return;
                        }
                        Err(e) => panic!("Failed to acquire next image: {e:?}"),
                    };

                if suboptimal {
                    recreate_swapchain = true;
                }

                // Copy data from CPU to GPU buffer.
                let buffer = {
                    CpuAccessibleBuffer::from_iter(
                        &memory_allocator,
                        BufferUsage {
                            transfer_src: true,
                            ..Default::default()
                        },
                        true,
                        image_buffer.iter().map(|v| *v),
                    )
                    .unwrap()
                };

                // There is supposed to be an elegant way to do this with subbuffers of a CpuBufferPool, but I can't
                // figure it out right now.
                // let buffer = buffer_pool
                //     .try_next(unsafe { *(image_buf.as_mut_ptr() as *mut [u8; 1920 * 1080 * 4]) })
                //     .unwrap();

                // We can only know which image to copy to after the chain has been acquired. The chain could be buffered
                // N images deep, so we need to copy specifically to the swapchain image that we acquired above.
                let swapchain_image = images[image_index as usize].clone();

                let mut builder = AutoCommandBufferBuilder::primary(
                    &command_buffer_allocator,
                    queue.queue_family_index(),
                    CommandBufferUsage::OneTimeSubmit,
                )
                .unwrap();

                // Only need a simple command queue. We just upload the buffer to the swapchain image directly.
                // This _does_ require an extension.
                builder
                    .copy_buffer_to_image(CopyBufferToImageInfo::buffer_image(
                        buffer.clone(),
                        swapchain_image,
                    ))
                    .unwrap();
                let command_buffer = builder.build().unwrap();

                let future = previous_frame_end
                    .take()
                    .unwrap()
                    .join(acquire_future)
                    .then_execute(queue.clone(), command_buffer)
                    .unwrap()
                    .then_swapchain_present(
                        queue.clone(),
                        SwapchainPresentInfo::swapchain_image_index(swapchain.clone(), image_index),
                    )
                    .then_signal_fence_and_flush();

                match future {
                    Ok(future) => {
                        previous_frame_end = Some(future.boxed());
                    }
                    Err(FlushError::OutOfDate) => {
                        recreate_swapchain = true;
                        previous_frame_end = Some(sync::now(device.clone()).boxed());
                    }
                    Err(e) => {
                        println!("Failed to flush future: {e:?}");
                        previous_frame_end = Some(sync::now(device.clone()).boxed());
                    }
                }
            }
            _ => (),
        }
    });
}
